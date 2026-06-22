package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// kscMockServer routes KSC Open API calls to canned JSON responses keyed by
// "Class.Method" and records the requests it observed.
type kscMockServer struct {
	t         *testing.T
	responses map[string]string
	observed  []string
}

func (m *kscMockServer) install() func() {
	original := newKSCHTTPClient
	newKSCHTTPClient = func(_ time.Duration) *http.Client {
		return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			method := strings.TrimPrefix(r.URL.Path, kscAPIPrefix)
			m.observed = append(m.observed, method)
			if got := r.Header.Get("Authorization"); got != "KSCT unit-token" {
				m.t.Errorf("Authorization header = %q", got)
			}
			if r.Header.Get("Content-Type") != "application/json" {
				m.t.Errorf("Content-Type = %q", r.Header.Get("Content-Type"))
			}
			body, ok := m.responses[method]
			if !ok {
				m.t.Fatalf("unexpected KSC call %q", method)
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(body)),
				Request:    r,
			}, nil
		})}
	}
	return func() { newKSCHTTPClient = original }
}

func configureKSC(t *testing.T) {
	t.Setenv("KSC_AUTHORIZATION", "KSCT unit-token")
	t.Setenv("KSC_SESSION", "")
	t.Setenv("KSC_BASE_URL", "https://ksc.unit.test:13299")
}

func TestKSCCallReturnsRetVal(t *testing.T) {
	configureKSC(t)
	mock := &kscMockServer{t: t, responses: map[string]string{
		"Session.StartSession": `{"PxgRetVal":"session-xyz"}`,
	}}
	defer mock.install()()

	result, err := kscCall(context.Background(), "Session", "StartSession", nil)
	if err != nil {
		t.Fatalf("kscCall: %v", err)
	}
	if got := pxgRetVal(result); got != "session-xyz" {
		t.Fatalf("PxgRetVal = %v, want session-xyz", got)
	}
}

func TestKSCCallMapsPxgError(t *testing.T) {
	configureKSC(t)
	mock := &kscMockServer{t: t, responses: map[string]string{
		"HostGroup.GetStaticInfo": `{"PxgError":{"code":1281,"module":"KLSTD","message":"Access denied"}}`,
	}}
	defer mock.install()()

	_, err := kscCall(context.Background(), "HostGroup", "GetStaticInfo", map[string]interface{}{"pValues": []string{"x"}})
	if err == nil {
		t.Fatal("expected PxgError to surface as an error")
	}
	if !strings.Contains(err.Error(), "Access denied") || !strings.Contains(err.Error(), "KLSTD") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestKSCCallRequiresConfiguration(t *testing.T) {
	t.Setenv("KSC_AUTHORIZATION", "")
	t.Setenv("KSC_SESSION", "")
	if _, err := kscCall(context.Background(), "Session", "StartSession", nil); err == nil {
		t.Fatal("expected unconfigured KSC to error")
	}
}

func TestKSCFindAndDrainAccessor(t *testing.T) {
	configureKSC(t)
	mock := &kscMockServer{t: t, responses: map[string]string{
		"HostGroup.FindHosts":         `{"PxgRetVal":2,"strAccessor":"acc-1"}`,
		"ChunkAccessor.GetItemsCount": `{"PxgRetVal":2}`,
		"ChunkAccessor.GetItemsChunk": `{"pChunk":{"KLCSP_ITERATOR_ARRAY":[{"KLHST_WKS_HOSTNAME":"h1"},{"KLHST_WKS_HOSTNAME":"h2"}]}}`,
		"ChunkAccessor.Release":       `{}`,
	}}
	defer mock.install()()

	items, err := kscFindAndDrain(context.Background(), "FindHosts",
		map[string]interface{}{"vecFieldsToReturn": []string{"KLHST_WKS_HOSTNAME"}}, 100)
	if err != nil {
		t.Fatalf("kscFindAndDrain: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("got %d items, want 2", len(items))
	}
	// The accessor must always be released.
	released := false
	for _, call := range mock.observed {
		if call == "ChunkAccessor.Release" {
			released = true
		}
	}
	if !released {
		t.Fatalf("accessor was not released; observed = %v", mock.observed)
	}
}

func TestExtractAccessorFallback(t *testing.T) {
	if got := extractAccessor(map[string]interface{}{"PxgRetVal": float64(3), "wstrIterator": "it-9"}); got != "it-9" {
		t.Fatalf("extractAccessor = %q, want it-9", got)
	}
	if got := extractAccessor(map[string]interface{}{"PxgRetVal": float64(0)}); got != "" {
		t.Fatalf("extractAccessor with no accessor = %q, want empty", got)
	}
}

func TestKSCReadOnlyAllowList(t *testing.T) {
	for _, op := range kscOperations {
		if op.Class == "*" {
			continue
		}
		if !kscReadOnlyMethods[op.Class+"."+op.Method] {
			t.Errorf("operation %s.%s is published but not in the read-only allow-list", op.Class, op.Method)
		}
	}
	if kscReadOnlyMethods["HostGroup.RemoveHost"] {
		t.Error("mutating method HostGroup.RemoveHost must not be allow-listed")
	}
}

func TestExtractChunkArrayShapes(t *testing.T) {
	var decoded map[string]interface{}
	_ = json.Unmarshal([]byte(`{"pChunk":{"KLCSP_ITERATOR_ARRAY":[{"a":1}]}}`), &decoded)
	if got := extractChunkArray(decoded); len(got) != 1 {
		t.Fatalf("extractChunkArray pChunk shape: got %d", len(got))
	}
}
