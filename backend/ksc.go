package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// Kaspersky Security Center 15.2 Open API integration.
//
// The KSC Administration Server Open API speaks HTTP with JSON bodies (not
// JSON-RPC). Every method is invoked with:
//
//	POST {base}/api/v1.0/[Instance.]Class.Method
//	Content-Type: application/json
//	Authorization: <scheme>        (e.g. "KSCT <token>", "KSCBasic ...")
//	X-KSC-Session: <session id>    (alternative to Authorization)
//
// The request body is a JSON object of input parameters ({} when there are
// none). A success (HTTP 200) returns {"PxgRetVal": ..., <out params>}; a
// failure returns {"PxgError": {"code", "module", "message"}}.
//
// Reference: https://support.kaspersky.com/help/KSC/15.2/KSCAPI/

const kscDefaultBaseURL = "https://localhost:13299"
const kscAPIPrefix = "/api/v1.0/"

var newKSCHTTPClient = func(timeout time.Duration) *http.Client {
	insecure := strings.EqualFold(strings.TrimSpace(os.Getenv("KSC_INSECURE_SKIP_VERIFY")), "true")
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: insecure, //nolint:gosec // KSC servers commonly present self-signed certs; opt-in via env.
		},
	}
	return &http.Client{Timeout: timeout, Transport: transport}
}

// kscOperation documents a KSC Open API method exposed through this backend.
type kscOperation struct {
	Name            string `json:"name"`
	Class           string `json:"class"`
	Method          string `json:"method"`
	ApplicationPath string `json:"applicationPath"`
	Description     string `json:"description"`
}

// kscReadOnlyMethods is the allow-list of KSC methods the generic call proxy
// accepts. It is intentionally limited to read-only / session operations so the
// proxy cannot be abused to mutate the Administration Server.
var kscReadOnlyMethods = map[string]bool{
	"Session.StartSession":            true,
	"Session.Ping":                    true,
	"Session.EndSession":              true,
	"Session.CreateToken":             true,
	"HostGroup.FindHosts":             true,
	"HostGroup.FindGroups":            true,
	"HostGroup.GetStaticInfo":         true,
	"HostGroup.GetRunTimeInfo":        true,
	"HostGroup.GetHostInfo":           true,
	"HostGroup.GetGroupInfo":          true,
	"HostGroup.GetGroupInfoEx":        true,
	"HostGroup.GetSubgroups":          true,
	"HostGroup.GetDomains":            true,
	"HostTagsApi.GetHostTags":         true,
	"HostTagsApi.GetHostsTags":        true,
	"LicenseKeys.EnumKeys":            true,
	"LicenseKeys.GetKeyData":          true,
	"ServerHierarchy.GetChildServers": true,
	// Reports.
	"ReportManager.EnumReportTypes":           true,
	"ReportManager.GetReportTypeDetailedInfo": true,
	"ReportManager.EnumReports":               true,
	"ReportManager.GetReportInfo":             true,
	"ReportManager.GetReportIds":              true,
	"ReportManager.GetReportCommonData":       true,
	"ReportManager.GetAvailableDashboards":    true,
	// Generic server views (flat result-set iterators).
	"SrvView.ResetIterator":   true,
	"SrvView.GetRecordCount":  true,
	"SrvView.GetRecordRange":  true,
	"SrvView.ReleaseIterator": true,
	// Software / hardware inventory.
	"InventoryApi.GetInvProductsList": true,
	"InventoryApi.GetInvPatchesList":  true,
	"InventoryApi.GetObservedApps":    true,
	"InventoryApi.GetHostInvProducts": true,
	"InventoryApi.GetHostInvPatches":  true,
	// Tasks (read-only).
	"Tasks.GetTask":            true,
	"Tasks.GetTaskData":        true,
	"Tasks.GetTaskStatistics2": true,
	"Tasks.GetTaskHistory":     true,
	"Tasks.GetAllTasksOfHost":  true,
	// Events.
	"EventProcessingFactory.CreateEventProcessing":         true,
	"EventProcessingFactory.CreateEventProcessing2":        true,
	"EventProcessingFactory.CreateEventProcessingForHost":  true,
	"EventProcessingFactory.CreateEventProcessingForHost2": true,
	"EventProcessing.GetRecordCount":                       true,
	"EventProcessing.GetRecordRange":                       true,
	"EventProcessing.ReleaseIterator":                      true,
	// Policies (read-only).
	"Policy.GetPolicyData":                true,
	"Policy.GetPolicyContents":            true,
	"Policy.GetPoliciesForGroup":          true,
	"Policy.GetEffectivePoliciesForGroup": true,
	"Policy.GetOutbreakPolicies":          true,
	// Chunk accessor (drives Find*/Enum* result sets).
	"ChunkAccessor.GetItemsCount": true,
	"ChunkAccessor.GetItemsChunk": true,
	"ChunkAccessor.Release":       true,
}

var kscOperations = []kscOperation{
	{Name: "Open authenticated session", Class: "Session", Method: "StartSession", ApplicationPath: "POST /api/ksc/session", Description: "Authenticate and obtain a session id reused by later calls."},
	{Name: "Administration server info", Class: "HostGroup", Method: "GetStaticInfo", ApplicationPath: "GET /api/ksc/server-info", Description: "Static Administration Server attributes (version, build, server id)."},
	{Name: "Administration groups", Class: "HostGroup", Method: "FindGroups", ApplicationPath: "GET /api/ksc/groups", Description: "Enumerate administration groups via a chunk accessor."},
	{Name: "Managed hosts", Class: "HostGroup", Method: "FindHosts", ApplicationPath: "GET /api/ksc/hosts", Description: "Enumerate managed devices via a chunk accessor."},
	{Name: "License keys", Class: "LicenseKeys", Method: "EnumKeys", ApplicationPath: "GET /api/ksc/licenses", Description: "Enumerate licenses installed on the server via a chunk accessor."},
	{Name: "Software inventory", Class: "InventoryApi", Method: "GetInvProductsList", ApplicationPath: "GET /api/ksc/software", Description: "Acquire the software applications inventory across managed devices."},
	{Name: "Reports", Class: "ReportManager", Method: "EnumReports", ApplicationPath: "GET /api/ksc/reports", Description: "Enumerate report definitions available on the server."},
	{Name: "Recent events", Class: "EventProcessingFactory", Method: "CreateEventProcessing2", ApplicationPath: "GET /api/ksc/events", Description: "Read recent administration events via an event-processing iterator."},
	{Name: "Generic method call", Class: "*", Method: "*", ApplicationPath: "POST /api/ksc/call", Description: "Invoke any allow-listed read-only KSC method directly."},
}

type kscCallRequest struct {
	Class  string                 `json:"class" binding:"required"`
	Method string                 `json:"method" binding:"required"`
	Params map[string]interface{} `json:"params"`
}

// kscError represents a PxgError returned by the Administration Server.
type kscError struct {
	Status  int
	Code    float64
	Module  string
	Message string
}

func (e *kscError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("KSC error %d (%s): %s", int(e.Code), e.Module, e.Message)
	}
	return fmt.Sprintf("KSC upstream returned HTTP %d", e.Status)
}

func kscConfigured() bool {
	return kscAuthorizationHeader() != "" ||
		strings.TrimSpace(os.Getenv("KSC_SESSION")) != "" ||
		strings.TrimSpace(os.Getenv("KSC_COOKIE")) != "" ||
		strings.TrimSpace(os.Getenv("KSC_ACCESS_TOKEN")) != ""
}

// kscCookieHeader builds the Cookie header value for the Kaspersky Next / ES
// Cloud console gateway, which authenticates via an `access_token` JWT cookie.
// KSC_ACCESS_TOKEN supplies just the JWT; KSC_COOKIE supplies a full raw cookie
// string (and wins if both are set).
func kscCookieHeader() string {
	if cookie := strings.TrimSpace(os.Getenv("KSC_COOKIE")); cookie != "" {
		return cookie
	}
	if token := strings.TrimSpace(os.Getenv("KSC_ACCESS_TOKEN")); token != "" {
		return "access_token=" + token
	}
	return ""
}

// kscAuthorizationHeader resolves the Authorization header value. The Kaspersky
// Next / Endpoint Security Cloud console gateway expects an OAuth Bearer JWT, so
// KSC_BEARER_TOKEN is auto-prefixed with "Bearer ". On-prem KSC accepts the raw
// scheme (KSCT/KSCWT/KSCBasic) supplied verbatim via KSC_AUTHORIZATION.
func kscAuthorizationHeader() string {
	if bearer := strings.TrimSpace(os.Getenv("KSC_BEARER_TOKEN")); bearer != "" {
		if strings.HasPrefix(strings.ToLower(bearer), "bearer ") {
			return bearer
		}
		return "Bearer " + bearer
	}
	return strings.TrimSpace(os.Getenv("KSC_AUTHORIZATION"))
}

// kscAuthScheme reports the auth scheme in use for status/diagnostics without
// leaking the credential itself.
func kscAuthScheme() string {
	header := kscAuthorizationHeader()
	if header == "" {
		if kscCookieHeader() != "" {
			return "Cookie (access_token)"
		}
		if strings.TrimSpace(os.Getenv("KSC_SESSION")) != "" {
			return "X-KSC-Session"
		}
		return "none"
	}
	if idx := strings.IndexByte(header, ' '); idx > 0 {
		return header[:idx]
	}
	return "custom"
}

func kscBaseURL() string {
	return strings.TrimRight(envOrDefault("KSC_BASE_URL", kscDefaultBaseURL), "/")
}

func registerKSCRoutes(router *gin.Engine) {
	router.GET("/api/ksc/status", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"product":    "Kaspersky Next / Endpoint Security Cloud — KSC 15.2 Open API",
			"baseUrl":    kscBaseURL(),
			"configured": kscConfigured(),
			"authScheme": kscAuthScheme(),
			"transport":  "HTTP+JSON, POST /api/v1.0/Class.Method, TLS 1.2",
			"operations": kscOperations,
		})
	})

	router.GET("/api/ksc/methods", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"operations": kscOperations})
	})

	router.POST("/api/ksc/session", func(c *gin.Context) {
		result, err := kscCall(c.Request.Context(), "Session", "StartSession", nil)
		if err != nil {
			writeKSCError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"sessionId": pxgRetVal(result), "result": result})
	})

	router.GET("/api/ksc/server-info", func(c *gin.Context) {
		params := map[string]interface{}{
			"pValues": []string{
				"KLADMSRV_SERVER_VERSION_ID",
				"KLADMSRV_VSID",
				"KLADMSRV_B2B_CLOUD_MODE",
				"KLADMSRV_PRODUCT_FULL_VERSION",
				"KLADMSRV_PRODUCT_NAME",
			},
		}
		result, err := kscCall(c.Request.Context(), "HostGroup", "GetStaticInfo", params)
		if err != nil {
			writeKSCError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"serverInfo": pxgRetVal(result), "result": result})
	})

	router.GET("/api/ksc/groups", func(c *gin.Context) {
		items, err := kscFindAndDrain(c.Request.Context(), "FindGroups",
			map[string]interface{}{
				"vecFieldsToReturn": []string{"id", "name", "parentId", "grp_full_name", "creationDate"},
				"lMaxLifeTime":      60,
			}, kscLimit(c))
		if err != nil {
			writeKSCError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"count": len(items), "groups": items})
	})

	router.GET("/api/ksc/hosts", func(c *gin.Context) {
		items, err := kscFindAndDrain(c.Request.Context(), "FindHosts",
			map[string]interface{}{
				"vecFieldsToReturn": []string{"KLHST_WKS_HOSTNAME", "KLHST_WKS_DN", "KLHST_WKS_OS_NAME", "KLHST_WKS_STATUS", "KLHST_WKS_LAST_VISIBLE"},
				"lMaxLifeTime":      60,
			}, kscLimit(c))
		if err != nil {
			writeKSCError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"count": len(items), "hosts": items})
	})

	router.GET("/api/ksc/licenses", func(c *gin.Context) {
		items, err := kscEnumAndDrain(c.Request.Context(), "LicenseKeys", "EnumKeys",
			map[string]interface{}{
				"pFields":     []string{"KLLIC_SERIAL", "KLLIC_PROD_NAME", "KLLIC_LIMIT_DATE", "KLLIC_KEY_TYPE", "KLLIC_HOSTS_COUNT"},
				"lTimeoutSec": 60,
			}, kscLimit(c))
		if err != nil {
			writeKSCError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"count": len(items), "licenses": items})
	})

	router.GET("/api/ksc/software", func(c *gin.Context) {
		result, err := kscCall(c.Request.Context(), "InventoryApi", "GetInvProductsList", map[string]interface{}{})
		if err != nil {
			writeKSCError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"software": pxgRetVal(result), "result": result})
	})

	router.GET("/api/ksc/reports", func(c *gin.Context) {
		result, err := kscCall(c.Request.Context(), "ReportManager", "EnumReports", map[string]interface{}{})
		if err != nil {
			writeKSCError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"reports": pxgRetVal(result), "result": result})
	})

	router.GET("/api/ksc/events", func(c *gin.Context) {
		create, err := kscCall(c.Request.Context(), "EventProcessingFactory", "CreateEventProcessing2",
			map[string]interface{}{
				"strDomainName": "",
				"strHostName":   "",
				"strProduct":    "",
				"strVersion":    "",
				"pFields2Return": []string{
					"GNRL_EA_DESCRIPTION", "KLEVP_EVENT_TYPE", "event_type_display_name",
					"GNRL_EA_SEVERITY", "hostname", "rise_time",
				},
				"pFields2Order": []interface{}{},
				"eventType":     "",
			})
		if err != nil {
			writeKSCError(c, err)
			return
		}
		iterator := extractAccessor(create)
		if iterator == "" {
			c.JSON(http.StatusOK, gin.H{"count": 0, "events": []interface{}{}})
			return
		}
		items, err := drainEventIterator(c.Request.Context(), iterator, kscLimit(c))
		if err != nil {
			writeKSCError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"count": len(items), "events": items})
	})

	router.POST("/api/ksc/call", func(c *gin.Context) {
		var req kscCallRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "class and method are required"})
			return
		}
		req.Class = strings.TrimSpace(req.Class)
		req.Method = strings.TrimSpace(req.Method)
		if !kscReadOnlyMethods[req.Class+"."+req.Method] {
			c.JSON(http.StatusForbidden, gin.H{"error": fmt.Sprintf("%s.%s is not an allow-listed read-only KSC method", req.Class, req.Method)})
			return
		}
		result, err := kscCall(c.Request.Context(), req.Class, req.Method, req.Params)
		if err != nil {
			writeKSCError(c, err)
			return
		}
		c.JSON(http.StatusOK, gin.H{"class": req.Class, "method": req.Method, "result": result})
	})
}

func kscLimit(c *gin.Context) int {
	limit := 100
	if raw := strings.TrimSpace(c.Query("limit")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 && parsed <= 1000 {
			limit = parsed
		}
	}
	return limit
}

// kscFindAndDrain runs a HostGroup.Find* method, then drains the returned
// chunk accessor into a slice of records.
func kscFindAndDrain(ctx context.Context, method string, params map[string]interface{}, limit int) ([]interface{}, error) {
	result, err := kscCall(ctx, "HostGroup", method, params)
	if err != nil {
		return nil, err
	}
	accessor := extractAccessor(result)
	if accessor == "" {
		return []interface{}{}, nil
	}
	return drainAccessor(ctx, accessor, limit)
}

// kscEnumAndDrain runs an Enum* method on the given class then drains the
// returned chunk accessor.
func kscEnumAndDrain(ctx context.Context, class, method string, params map[string]interface{}, limit int) ([]interface{}, error) {
	result, err := kscCall(ctx, class, method, params)
	if err != nil {
		return nil, err
	}
	accessor := extractAccessor(result)
	if accessor == "" {
		return []interface{}{}, nil
	}
	return drainAccessor(ctx, accessor, limit)
}

// drainAccessor pages through a KSC result set via ChunkAccessor and always
// releases the accessor afterwards.
func drainAccessor(ctx context.Context, accessor string, limit int) ([]interface{}, error) {
	defer func() {
		_, _ = kscCall(ctx, "ChunkAccessor", "Release", map[string]interface{}{"strAccessor": accessor})
	}()

	countResult, err := kscCall(ctx, "ChunkAccessor", "GetItemsCount", map[string]interface{}{"strAccessor": accessor})
	if err != nil {
		return nil, err
	}
	total := limit
	if n, ok := pxgRetVal(countResult).(float64); ok && int(n) < total {
		total = int(n)
	}

	items := make([]interface{}, 0, total)
	const page = 100
	for start := 0; start < total; start += page {
		count := page
		if start+count > total {
			count = total - start
		}
		chunk, err := kscCall(ctx, "ChunkAccessor", "GetItemsChunk", map[string]interface{}{
			"strAccessor": accessor,
			"nStart":      start,
			"nCount":      count,
		})
		if err != nil {
			return nil, err
		}
		items = append(items, extractChunkArray(chunk)...)
	}
	return items, nil
}

// drainEventIterator pages through an EventProcessing result-set. Unlike
// ChunkAccessor, this family uses GetRecordCount / GetRecordRange(nStart, nEnd)
// and ReleaseIterator, and returns records under KLEVP_EVENT_RANGE_ARRAY.
func drainEventIterator(ctx context.Context, iterator string, limit int) ([]interface{}, error) {
	defer func() {
		_, _ = kscCall(ctx, "EventProcessing", "ReleaseIterator", map[string]interface{}{"strIteratorId": iterator})
	}()

	countResult, err := kscCall(ctx, "EventProcessing", "GetRecordCount", map[string]interface{}{"strIteratorId": iterator})
	if err != nil {
		return nil, err
	}
	total := limit
	if n, ok := pxgRetVal(countResult).(float64); ok && int(n) < total {
		total = int(n)
	}

	items := make([]interface{}, 0, total)
	const page = 100
	for start := 0; start < total; start += page {
		end := start + page
		if end > total {
			end = total
		}
		chunk, err := kscCall(ctx, "EventProcessing", "GetRecordRange", map[string]interface{}{
			"strIteratorId": iterator,
			"nStart":        start,
			"nEnd":          end,
		})
		if err != nil {
			return nil, err
		}
		items = append(items, extractEventArray(chunk)...)
	}
	return items, nil
}

// extractEventArray pulls event records out of an EventProcessing.GetRecordRange
// response (records live under pParamsEvents.KLEVP_EVENT_RANGE_ARRAY).
func extractEventArray(chunk map[string]interface{}) []interface{} {
	candidates := []interface{}{chunk["pParamsEvents"], chunk["PxgRetVal"], chunk}
	for _, candidate := range candidates {
		obj, ok := candidate.(map[string]interface{})
		if !ok {
			continue
		}
		if arr, ok := obj["KLEVP_EVENT_RANGE_ARRAY"].([]interface{}); ok {
			return arr
		}
	}
	return nil
}

// kscCall invokes a single KSC Open API method and returns the decoded JSON
// response object.
func kscCall(ctx context.Context, class, method string, params map[string]interface{}) (map[string]interface{}, error) {
	base := kscBaseURL()
	if _, err := url.Parse(base); err != nil {
		return nil, fmt.Errorf("invalid KSC base URL: %w", err)
	}
	if !kscConfigured() {
		return nil, errors.New("KSC_AUTHORIZATION or KSC_SESSION is not configured")
	}

	body := []byte("{}")
	if len(params) > 0 {
		encoded, err := json.Marshal(params)
		if err != nil {
			return nil, err
		}
		body = encoded
	}

	target := base + kscAPIPrefix + class + "." + method
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if auth := kscAuthorizationHeader(); auth != "" {
		req.Header.Set("Authorization", auth)
	}
	if session := strings.TrimSpace(os.Getenv("KSC_SESSION")); session != "" {
		req.Header.Set("X-KSC-Session", session)
	}
	if vserver := strings.TrimSpace(os.Getenv("KSC_VSERVER")); vserver != "" {
		req.Header.Set("X-KSC-VServer", vserver)
	}
	// The Kaspersky Next / ES Cloud console gateway authenticates browser
	// sessions with a cookie (+ XSRF token) rather than a Bearer header.
	if cookie := kscCookieHeader(); cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	if xsrf := strings.TrimSpace(os.Getenv("KSC_XSRF_TOKEN")); xsrf != "" {
		req.Header.Set("X-XSRF-TOKEN", xsrf)
	}

	client := newKSCHTTPClient(60 * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxUpstreamResponse+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxUpstreamResponse {
		return nil, errors.New("KSC upstream response exceeded 4 MiB")
	}

	var decoded map[string]interface{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &decoded); err != nil {
			return nil, fmt.Errorf("KSC upstream returned a non-JSON response (HTTP %d)", resp.StatusCode)
		}
	}

	if pxg, ok := decoded["PxgError"].(map[string]interface{}); ok {
		ke := &kscError{Status: resp.StatusCode}
		if code, ok := pxg["code"].(float64); ok {
			ke.Code = code
		}
		ke.Module, _ = pxg["module"].(string)
		ke.Message, _ = pxg["message"].(string)
		return nil, ke
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &kscError{Status: resp.StatusCode, Message: safeUpstreamBody(raw)}
	}
	if decoded == nil {
		decoded = map[string]interface{}{}
	}
	return decoded, nil
}

func pxgRetVal(result map[string]interface{}) interface{} {
	if result == nil {
		return nil
	}
	return result["PxgRetVal"]
}

// extractAccessor finds the server-side iterator/accessor string returned by a
// Find*/Enum* call. KSC names this out parameter differently per method
// (strAccessor, wstrAccessor, wstrIterator, lpHostsList), so we probe known
// keys and fall back to the first non-empty string value.
func extractAccessor(result map[string]interface{}) string {
	for _, key := range []string{"strAccessor", "wstrAccessor", "wstrIterator", "lpHostsList", "lpGroupsList"} {
		if v, ok := result[key].(string); ok && v != "" {
			return v
		}
	}
	for key, value := range result {
		if key == "PxgRetVal" {
			continue
		}
		if v, ok := value.(string); ok && v != "" {
			return v
		}
	}
	return ""
}

// extractChunkArray pulls the records out of a ChunkAccessor.GetItemsChunk
// response. The records live under pChunk.KLCSP_ITERATOR_ARRAY.
func extractChunkArray(chunk map[string]interface{}) []interface{} {
	candidates := []interface{}{chunk["pChunk"], chunk["PxgRetVal"], chunk}
	for _, candidate := range candidates {
		obj, ok := candidate.(map[string]interface{})
		if !ok {
			continue
		}
		if arr, ok := obj["KLCSP_ITERATOR_ARRAY"].([]interface{}); ok {
			return arr
		}
	}
	return nil
}

func writeKSCError(c *gin.Context, err error) {
	var ke *kscError
	if errors.As(err, &ke) {
		status := http.StatusBadGateway
		if ke.Status == http.StatusUnauthorized || ke.Status == http.StatusForbidden || ke.Status == http.StatusTooManyRequests {
			status = ke.Status
		}
		c.JSON(status, gin.H{"error": ke.Error(), "upstreamStatus": ke.Status, "code": ke.Code, "module": ke.Module})
		return
	}
	status := http.StatusBadGateway
	if strings.Contains(err.Error(), "is not configured") {
		status = http.StatusServiceUnavailable
	}
	c.JSON(status, gin.H{"error": err.Error()})
}
