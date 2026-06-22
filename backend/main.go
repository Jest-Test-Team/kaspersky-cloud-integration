package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type openAPISpec struct {
	Info struct {
		Title       string `json:"title"`
		Description string `json:"description"`
		Version     string `json:"version"`
	} `json:"info"`
	Servers []struct {
		URL string `json:"url"`
	} `json:"servers"`
	Paths map[string]map[string]operation `json:"paths"`
}

type operation struct {
	Summary     string                   `json:"summary"`
	Description string                   `json:"description"`
	OperationID string                   `json:"operationId"`
	Tags        []string                 `json:"tags"`
	RequestBody map[string]interface{}   `json:"requestBody"`
	Parameters  []map[string]interface{} `json:"parameters"`
}

type endpointSummary struct {
	Path        string   `json:"path"`
	Method      string   `json:"method"`
	Summary     string   `json:"summary,omitempty"`
	Description string   `json:"description,omitempty"`
	OperationID string   `json:"operationId,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	HasBody     bool     `json:"hasBody"`
}

type specSummary struct {
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Version     string            `json:"version"`
	TargetURL   string            `json:"targetUrl"`
	Endpoints   []endpointSummary `json:"endpoints"`
}

type proxyRequest struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Query   map[string]string `json:"query"`
	Headers map[string]string `json:"headers"`
	Body    json.RawMessage   `json:"body"`
}

type proxyResponse struct {
	Status     int               `json:"status"`
	StatusText string            `json:"statusText"`
	Headers    map[string]string `json:"headers"`
	Body       interface{}       `json:"body"`
	RawBody    string            `json:"rawBody,omitempty"`
}

func main() {
	spec, specPath, err := loadSpec()
	if err != nil {
		log.Printf("Legacy Endpoint Security swagger disabled: %v", err)
		spec = &openAPISpec{}
		spec.Info.Title = "Kaspersky Integration API"
		spec.Info.Description = "Kaspersky Threat Intelligence and Security Center integration"
		spec.Info.Version = "1.0.0"
	}

	targetURL := strings.TrimRight(envOrDefault("KES_API_BASE_URL", firstServerURL(spec, "http://localhost:8021")), "/")
	summary := buildSpecSummary(spec, targetURL)

	router := gin.Default()
	if err := router.SetTrustedProxies(nil); err != nil {
		log.Fatalf("configure trusted proxies: %v", err)
	}
	router.Use(corsMiddleware())

	router.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"ok":                     true,
			"swaggerPath":            specPath,
			"targetUrl":              targetURL,
			"intelligenceConfigured": strings.TrimSpace(os.Getenv("KASPERSKY_TIP_API_KEY")) != "",
			"kscConfigured":          strings.TrimSpace(os.Getenv("KSC_AUTHORIZATION")) != "" || strings.TrimSpace(os.Getenv("KSC_SESSION")) != "",
		})
	})
	registerIntegrationRoutes(router)

	router.GET("/api/spec/summary", func(c *gin.Context) {
		c.JSON(http.StatusOK, summary)
	})

	router.POST("/api/proxy", func(c *gin.Context) {
		var req proxyRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		resp, err := callTarget(c.Request.Context(), targetURL, req)
		if err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, resp)
	})

	addr := envOrDefault("BACKEND_ADDR", ":8080")
	log.Printf("Loaded %d API operations from %s", len(summary.Endpoints), specPath)
	log.Printf("Proxy target: %s", targetURL)
	startAgentDiagnostics()
	log.Printf("Listening on %s", addr)
	if err := router.Run(addr); err != nil {
		log.Fatal(err)
	}
}

func loadSpec() (*openAPISpec, string, error) {
	candidates := []string{}
	if configured := strings.TrimSpace(os.Getenv("KES_SWAGGER_PATH")); configured != "" {
		candidates = append(candidates, configured)
	}
	candidates = append(candidates, "swagger.json", "../swagger.json")

	for _, candidate := range candidates {
		data, err := os.ReadFile(candidate)
		if err != nil {
			continue
		}

		var spec openAPISpec
		if err := json.Unmarshal(data, &spec); err != nil {
			return nil, candidate, err
		}
		if len(spec.Paths) == 0 {
			return nil, candidate, errors.New("swagger spec has no paths")
		}

		absPath, err := filepath.Abs(candidate)
		if err != nil {
			return &spec, candidate, nil
		}
		return &spec, absPath, nil
	}

	return nil, "", errors.New("set KES_SWAGGER_PATH or run from the repository root/backend directory")
}

func firstServerURL(spec *openAPISpec, fallback string) string {
	if len(spec.Servers) == 0 || strings.TrimSpace(spec.Servers[0].URL) == "" {
		return fallback
	}
	return spec.Servers[0].URL
}

func buildSpecSummary(spec *openAPISpec, targetURL string) specSummary {
	endpoints := make([]endpointSummary, 0, len(spec.Paths))
	for path, methods := range spec.Paths {
		for method, op := range methods {
			if method == "parameters" {
				continue
			}
			endpoints = append(endpoints, endpointSummary{
				Path:        path,
				Method:      strings.ToUpper(method),
				Summary:     op.Summary,
				Description: op.Description,
				OperationID: op.OperationID,
				Tags:        op.Tags,
				HasBody:     op.RequestBody != nil,
			})
		}
	}

	sort.Slice(endpoints, func(i, j int) bool {
		if endpoints[i].Path == endpoints[j].Path {
			return endpoints[i].Method < endpoints[j].Method
		}
		return endpoints[i].Path < endpoints[j].Path
	})

	return specSummary{
		Title:       spec.Info.Title,
		Description: spec.Info.Description,
		Version:     spec.Info.Version,
		TargetURL:   targetURL,
		Endpoints:   endpoints,
	}
}

func callTarget(ctx context.Context, base string, req proxyRequest) (*proxyResponse, error) {
	method := strings.ToUpper(strings.TrimSpace(req.Method))
	if method == "" {
		method = http.MethodGet
	}

	path := "/" + strings.TrimLeft(req.Path, "/")
	target, err := url.Parse(base + path)
	if err != nil {
		return nil, err
	}

	query := target.Query()
	for key, value := range req.Query {
		query.Set(key, value)
	}
	target.RawQuery = query.Encode()

	var body io.Reader
	if len(req.Body) > 0 && string(req.Body) != "null" {
		body = bytes.NewReader(req.Body)
	}

	httpReq, err := http.NewRequest(method, target.String(), body)
	if err != nil {
		return nil, err
	}
	httpReq = httpReq.WithContext(ctx)
	if body != nil {
		httpReq.Header.Set("Content-Type", "application/json")
	}
	for key, value := range req.Headers {
		if strings.EqualFold(key, "host") || strings.EqualFold(key, "content-length") {
			continue
		}
		httpReq.Header.Set(key, value)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	httpResp, err := client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer httpResp.Body.Close()

	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, err
	}

	headers := make(map[string]string)
	for key, values := range httpResp.Header {
		headers[key] = strings.Join(values, ", ")
	}

	var parsed interface{}
	rawBody := string(respBody)
	if len(respBody) > 0 && json.Unmarshal(respBody, &parsed) == nil {
		rawBody = ""
	} else {
		parsed = rawBody
	}

	return &proxyResponse{
		Status:     httpResp.StatusCode,
		StatusText: httpResp.Status,
		Headers:    headers,
		Body:       parsed,
		RawBody:    rawBody,
	}, nil
}

func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", envOrDefault("CORS_ALLOW_ORIGIN", "http://localhost:3000"))
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

func envOrDefault(key string, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func startAgentDiagnostics() {
	if strings.ToLower(envOrDefault("ENABLE_AGENT_DIAGNOSTIC_PORTS", "false")) != "true" {
		return
	}

	plainAddr := envOrDefault("AGENT_PLAIN_ADDR", ":14000")
	tlsAddr := envOrDefault("AGENT_TLS_ADDR", ":13000")

	go func() {
		if err := listenForAgentConnections(plainAddr, nil); err != nil {
			log.Printf("agent diagnostic listener %s stopped: %v", plainAddr, err)
		}
	}()

	cert, err := selfSignedCertificate()
	if err != nil {
		log.Printf("agent TLS diagnostic disabled: %v", err)
		return
	}
	go func() {
		if err := listenForAgentConnections(tlsAddr, &tls.Config{Certificates: []tls.Certificate{cert}}); err != nil {
			log.Printf("agent TLS diagnostic listener %s stopped: %v", tlsAddr, err)
		}
	}()

	log.Printf("Agent diagnostic listeners enabled on %s and %s", plainAddr, tlsAddr)
	log.Print("These listeners are only connectivity diagnostics; they do not implement Kaspersky Security Center.")
}

func listenForAgentConnections(addr string, tlsConfig *tls.Config) error {
	var listener net.Listener
	var err error
	if tlsConfig == nil {
		listener, err = net.Listen("tcp", addr)
	} else {
		listener, err = tls.Listen("tcp", addr, tlsConfig)
	}
	if err != nil {
		return err
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go handleAgentDiagnosticConnection(conn)
	}
}

func handleAgentDiagnosticConnection(conn net.Conn) {
	defer conn.Close()

	remote := conn.RemoteAddr().String()
	log.Printf("Agent diagnostic connection from %s", remote)

	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	buffer := make([]byte, 256)
	n, err := conn.Read(buffer)
	if err != nil && !errors.Is(err, io.EOF) {
		log.Printf("Agent diagnostic read from %s: %v", remote, err)
		return
	}
	if n > 0 {
		log.Printf("Agent diagnostic received %d bytes from %s: %x", n, remote, buffer[:n])
	}
}

func selfSignedCertificate() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if certPEM == nil || keyPEM == nil {
		return tls.Certificate{}, fmt.Errorf("failed to encode self-signed certificate")
	}

	return tls.X509KeyPair(certPEM, keyPEM)
}
