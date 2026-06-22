package main

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestClassifyIndicator(t *testing.T) {
	tests := []struct {
		input string
		kind  string
	}{
		{"44d88612fea8a8f36de82e1278abb02f", "hash"},
		{"8.8.8.8", "ip"},
		{"Example.COM", "domain"},
		{"https://example.com/a?b=c", "url"},
	}
	for _, test := range tests {
		kind, _, err := classifyIndicator(test.input)
		if err != nil {
			t.Fatalf("classifyIndicator(%q): %v", test.input, err)
		}
		if kind != test.kind {
			t.Fatalf("classifyIndicator(%q) kind = %q, want %q", test.input, kind, test.kind)
		}
	}
}

func TestClassifyIndicatorRejectsUnsupported(t *testing.T) {
	if _, _, err := classifyIndicator("not an indicator"); err == nil {
		t.Fatal("expected invalid indicator to be rejected")
	}
}

func TestAllPublishedEndpoints(t *testing.T) {
	type observedRequest struct {
		method string
		path   string
		query  string
		body   string
	}
	requests := make(chan observedRequest, 6)
	originalClientFactory := newHTTPClient
	newHTTPClient = func(_ time.Duration) *http.Client {
		return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			var body []byte
			if r.Body != nil {
				body, _ = io.ReadAll(r.Body)
			}
			requests <- observedRequest{method: r.Method, path: r.URL.Path, query: r.URL.Query().Get("request"), body: string(body)}
			if r.Header.Get("X-API-KEY") != "test-token" {
				t.Errorf("X-API-KEY = %q", r.Header.Get("X-API-KEY"))
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(`{"Zone":"Green"}`)),
				Request:    r,
			}, nil
		})}
	}
	t.Cleanup(func() { newHTTPClient = originalClientFactory })
	t.Setenv("KASPERSKY_TIP_API_KEY", "test-token")
	t.Setenv("KASPERSKY_TIP_BASE_URL", "https://unit.test")

	lookups := []struct {
		kind, value, path string
	}{
		{"hash", "44d88612fea8a8f36de82e1278abb02f", "/search/hash"},
		{"ip", "8.8.8.8", "/search/ip"},
		{"domain", "example.com", "/search/domain"},
		{"url", "https://example.com/", "/search/url"},
	}
	for _, lookup := range lookups {
		if _, err := lookupIntelligence(context.Background(), lookup.kind, lookup.value); err != nil {
			t.Fatalf("%s lookup: %v", lookup.kind, err)
		}
		request := <-requests
		if request.method != http.MethodGet || request.path != lookup.path || request.query != lookup.value {
			t.Errorf("%s request = %#v", lookup.kind, request)
		}
	}

	if _, err := scanIntelligenceFile(context.Background(), "fixture.txt", strings.NewReader("safe fixture")); err != nil {
		t.Fatalf("file scan: %v", err)
	}
	scan := <-requests
	if scan.method != http.MethodPost || scan.path != "/scan/file" || scan.body != "safe fixture" {
		t.Errorf("file scan request = %#v", scan)
	}

	if _, err := getIntelligenceFileReport(context.Background(), "44d88612fea8a8f36de82e1278abb02f"); err != nil {
		t.Fatalf("file report: %v", err)
	}
	report := <-requests
	if report.method != http.MethodPost || report.path != "/getresult/file" || report.query != "44d88612fea8a8f36de82e1278abb02f" {
		t.Errorf("file report request = %#v", report)
	}

	if len(supportedEndpoints) != 6 {
		t.Fatalf("published endpoint catalog contains %d entries, want 6", len(supportedEndpoints))
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}
