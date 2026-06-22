package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const maxUpstreamResponse = 4 << 20
const maxFileUpload = 256 << 20

var (
	hashPattern   = regexp.MustCompile(`(?i)^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$`)
	domainPattern = regexp.MustCompile(`(?i)^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
)

type intelligenceLookupRequest struct {
	Indicator string `json:"indicator" binding:"required"`
}

type integrationStatus struct {
	IntelligenceConfigured bool     `json:"intelligenceConfigured"`
	IntelligenceBaseURL    string   `json:"intelligenceBaseUrl"`
	SupportedOperations    []string `json:"supportedOperations"`
	CloudConsoleAPI        string   `json:"cloudConsoleApi"`
}

type fileReportRequest struct {
	Hash string `json:"hash" binding:"required"`
}

type upstreamError struct {
	Status int
	Body   string
}

func (e *upstreamError) Error() string {
	return fmt.Sprintf("Kaspersky upstream returned HTTP %d", e.Status)
}

func registerIntegrationRoutes(router *gin.Engine) {
	router.GET("/api/integrations/status", func(c *gin.Context) {
		c.JSON(http.StatusOK, currentIntegrationStatus())
	})

	router.POST("/api/intelligence/lookup", func(c *gin.Context) {
		var req intelligenceLookupRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "indicator is required"})
			return
		}

		kind, normalized, err := classifyIndicator(req.Indicator)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		result, err := lookupIntelligence(c.Request.Context(), kind, normalized)
		if err != nil {
			writeIntegrationError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"type": kind, "indicator": normalized, "result": result})
	})

	router.POST("/api/intelligence/file/scan", func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxFileUpload+(1<<20))
		fileHeader, err := c.FormFile("file")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "a multipart file field is required"})
			return
		}
		if fileHeader.Size > maxFileUpload {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "file exceeds Kaspersky's 256 MiB limit"})
			return
		}
		file, err := fileHeader.Open()
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "could not open uploaded file"})
			return
		}
		defer file.Close()
		result, err := scanIntelligenceFile(c.Request.Context(), filepath.Base(fileHeader.Filename), file)
		if err != nil {
			writeIntegrationError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"filename": filepath.Base(fileHeader.Filename), "result": result})
	})

	router.POST("/api/intelligence/file/report", func(c *gin.Context) {
		var req fileReportRequest
		if err := c.ShouldBindJSON(&req); err != nil || !hashPattern.MatchString(strings.TrimSpace(req.Hash)) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "a valid MD5, SHA-1, or SHA-256 hash is required"})
			return
		}
		result, err := getIntelligenceFileReport(c.Request.Context(), strings.ToLower(strings.TrimSpace(req.Hash)))
		if err != nil {
			writeIntegrationError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"hash": strings.ToLower(strings.TrimSpace(req.Hash)), "result": result})
	})

}

func currentIntegrationStatus() integrationStatus {
	return integrationStatus{
		IntelligenceConfigured: strings.TrimSpace(os.Getenv("KASPERSKY_TIP_API_KEY")) != "",
		IntelligenceBaseURL:    envOrDefault("KASPERSKY_TIP_BASE_URL", "https://opentip.kaspersky.com/api/v1"),
		SupportedOperations:    []string{"hash lookup", "IPv4 lookup", "domain lookup", "URL lookup", "file scan", "file report"},
		CloudConsoleAPI:        "not publicly available for Kaspersky Endpoint Security Cloud",
	}
}

func classifyIndicator(value string) (string, string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", "", errors.New("indicator is required")
	}
	if hashPattern.MatchString(value) {
		return "hash", strings.ToLower(value), nil
	}
	if ip := net.ParseIP(value); ip != nil && ip.To4() != nil {
		return "ip", ip.String(), nil
	}
	if parsed, err := url.ParseRequestURI(value); err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Hostname() != "" {
		return "url", value, nil
	}
	normalizedDomain := strings.ToLower(strings.TrimSuffix(value, "."))
	if domainPattern.MatchString(normalizedDomain) {
		return "domain", normalizedDomain, nil
	}
	return "", "", errors.New("indicator must be an MD5/SHA-1/SHA-256 hash, IPv4 address, domain, or HTTP(S) URL")
}

func lookupIntelligence(ctx context.Context, kind, indicator string) (interface{}, error) {
	apiKey := strings.TrimSpace(os.Getenv("KASPERSKY_TIP_API_KEY"))
	if apiKey == "" {
		return nil, errors.New("KASPERSKY_TIP_API_KEY is not configured")
	}

	base := strings.TrimRight(envOrDefault("KASPERSKY_TIP_BASE_URL", "https://opentip.kaspersky.com/api/v1"), "/")
	target, err := url.Parse(base + "/search/" + kind)
	if err != nil {
		return nil, fmt.Errorf("invalid intelligence base URL: %w", err)
	}
	query := target.Query()
	query.Set("request", indicator)
	target.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-KEY", apiKey)
	req.Header.Set("Accept", "application/json")
	return doKasperskyRequest(req)
}

func scanIntelligenceFile(ctx context.Context, filename string, file io.Reader) (interface{}, error) {
	target, apiKey, err := intelligenceTarget("/scan/file")
	if err != nil {
		return nil, err
	}
	query := target.Query()
	query.Set("filename", filename)
	target.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), file)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-KEY", apiKey)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Accept", "application/json")
	return doKasperskyRequestWithTimeout(req, 5*time.Minute)
}

func getIntelligenceFileReport(ctx context.Context, hash string) (interface{}, error) {
	target, apiKey, err := intelligenceTarget("/getresult/file")
	if err != nil {
		return nil, err
	}
	query := target.Query()
	query.Set("request", hash)
	target.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-API-KEY", apiKey)
	req.Header.Set("Accept", "application/json")
	return doKasperskyRequest(req)
}

func intelligenceTarget(path string) (*url.URL, string, error) {
	apiKey := strings.TrimSpace(os.Getenv("KASPERSKY_TIP_API_KEY"))
	if apiKey == "" {
		return nil, "", errors.New("KASPERSKY_TIP_API_KEY is not configured")
	}
	base := strings.TrimRight(envOrDefault("KASPERSKY_TIP_BASE_URL", "https://opentip.kaspersky.com/api/v1"), "/")
	target, err := url.Parse(base + path)
	if err != nil {
		return nil, "", fmt.Errorf("invalid intelligence base URL: %w", err)
	}
	return target, apiKey, nil
}

func doKasperskyRequest(req *http.Request) (interface{}, error) {
	return doKasperskyRequestWithTimeout(req, 30*time.Second)
}

func doKasperskyRequestWithTimeout(req *http.Request, timeout time.Duration) (interface{}, error) {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxUpstreamResponse+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxUpstreamResponse {
		return nil, errors.New("Kaspersky upstream response exceeded 4 MiB")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &upstreamError{Status: resp.StatusCode, Body: safeUpstreamBody(body)}
	}
	if len(body) == 0 {
		return map[string]interface{}{}, nil
	}
	var result interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, errors.New("Kaspersky upstream returned a non-JSON response")
	}
	return result, nil
}

func safeUpstreamBody(body []byte) string {
	message := strings.TrimSpace(string(body))
	if len(message) > 500 {
		message = message[:500]
	}
	return message
}

func writeIntegrationError(c *gin.Context, err error) {
	var upstream *upstreamError
	if errors.As(err, &upstream) {
		status := http.StatusBadGateway
		if upstream.Status == http.StatusUnauthorized || upstream.Status == http.StatusForbidden || upstream.Status == http.StatusTooManyRequests {
			status = upstream.Status
		}
		c.JSON(status, gin.H{"error": upstream.Error(), "upstreamStatus": upstream.Status, "details": upstream.Body})
		return
	}
	status := http.StatusBadGateway
	if strings.Contains(err.Error(), "is not configured") {
		status = http.StatusServiceUnavailable
	}
	c.JSON(status, gin.H{"error": err.Error()})
}
