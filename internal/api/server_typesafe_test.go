package api

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// typesafeCaptureExecutor stands in for the TypeSafe plugin executor. Like the plugin
// executor adapter it does not implement request preparation.
type typesafeCaptureExecutor struct {
	statusByAuth map[string]int
	bodyByAuth   map[string]string
	errByAuth    map[string]error
	authIDs      []string
	urls         []string
	bodies       []string
	headers      []http.Header
}

func (e *typesafeCaptureExecutor) Identifier() string { return typesafeProvider }

func (e *typesafeCaptureExecutor) Execute(context.Context, *auth.Auth, coreexecutor.Request, coreexecutor.Options) (coreexecutor.Response, error) {
	return coreexecutor.Response{}, nil
}

func (e *typesafeCaptureExecutor) ExecuteStream(context.Context, *auth.Auth, coreexecutor.Request, coreexecutor.Options) (*coreexecutor.StreamResult, error) {
	return nil, nil
}

func (e *typesafeCaptureExecutor) Refresh(_ context.Context, a *auth.Auth) (*auth.Auth, error) {
	return a, nil
}

func (e *typesafeCaptureExecutor) CountTokens(context.Context, *auth.Auth, coreexecutor.Request, coreexecutor.Options) (coreexecutor.Response, error) {
	return coreexecutor.Response{}, nil
}

func (e *typesafeCaptureExecutor) HttpRequest(ctx context.Context, selected *auth.Auth, req *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	e.authIDs = append(e.authIDs, selected.ID)
	if errCtx := ctx.Err(); errCtx != nil {
		return nil, errCtx
	}
	if errAuth := e.errByAuth[selected.ID]; errAuth != nil {
		return nil, errAuth
	}
	e.urls = append(e.urls, req.URL.String())
	e.bodies = append(e.bodies, string(body))
	e.headers = append(e.headers, req.Header.Clone())
	status := http.StatusOK
	if code, ok := e.statusByAuth[selected.ID]; ok {
		status = code
	}
	respBody := `{"model":"jev-latest","answers":{},"usage":{"input_tokens":120,"output_tokens":12}}`
	if custom, ok := e.bodyByAuth[selected.ID]; ok {
		respBody = custom
	}
	header := http.Header{"Content-Type": []string{"application/json"}}
	if status == http.StatusTooManyRequests {
		header.Set("Retry-After", "30")
	}
	return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(respBody))}, nil
}

func registerTypesafeAuths(t *testing.T, server *Server, auths ...*auth.Auth) {
	t.Helper()
	for _, credential := range auths {
		if _, err := server.handlers.AuthManager.Register(context.Background(), credential); err != nil {
			t.Fatalf("register TypeSafe auth %s: %v", credential.ID, err)
		}
	}
}

func newTypesafeAuth(id string, attributes map[string]string) *auth.Auth {
	return &auth.Auth{ID: id, Provider: typesafeProvider, Status: auth.StatusActive, Attributes: attributes}
}

func serveSystemOne(server *Server, body string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1/systemone", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	rr := httptest.NewRecorder()
	server.engine.ServeHTTP(rr, req)
	return rr
}

func TestTypesafeSystemOneForwardsRequestUnchanged(t *testing.T) {
	server := newTestServer(t)
	executor := &typesafeCaptureExecutor{}
	server.handlers.AuthManager.RegisterExecutor(executor)
	registerTypesafeAuths(t, server, newTypesafeAuth("typesafe-a.json", nil))

	const requestBody = `{"model":"jev-latest","state":"refund please","questions":{"billing":{"type":"noul"}}}`
	rr := serveSystemOne(server, requestBody, nil)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if len(executor.urls) != 1 || executor.urls[0] != "https://api.typesafe.ai/v1/systemone" {
		t.Fatalf("upstream URLs = %v, want TypeSafe System One", executor.urls)
	}
	if executor.bodies[0] != requestBody {
		t.Fatalf("upstream body = %q, want unchanged %q", executor.bodies[0], requestBody)
	}
	if got := executor.headers[0].Get("Authorization"); got != "" {
		t.Fatalf("client Authorization leaked upstream: %q", got)
	}
	if !strings.Contains(rr.Body.String(), `"input_tokens":120`) {
		t.Fatalf("response body = %s, want upstream response", rr.Body.String())
	}
}

func TestTypesafeSystemOneUsesCredentialBaseURLAndEncoding(t *testing.T) {
	server := newTestServer(t)
	executor := &typesafeCaptureExecutor{}
	server.handlers.AuthManager.RegisterExecutor(executor)
	registerTypesafeAuths(t, server, newTypesafeAuth("typesafe-a.json", map[string]string{"base_url": "https://eu.typesafe.example/"}))

	rr := serveSystemOne(server, "compressed-bytes", map[string]string{"Content-Encoding": "zstd"})

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", rr.Code, rr.Body.String())
	}
	if executor.urls[0] != "https://eu.typesafe.example/v1/systemone" {
		t.Fatalf("upstream URL = %q", executor.urls[0])
	}
	if got := executor.headers[0].Get("Content-Encoding"); got != "zstd" {
		t.Fatalf("Content-Encoding = %q, want zstd forwarded", got)
	}
	if executor.bodies[0] != "compressed-bytes" {
		t.Fatalf("upstream body = %q, want raw bytes", executor.bodies[0])
	}
}

func TestTypesafeSystemOneRotatesPastRateLimitedKey(t *testing.T) {
	server := newTestServer(t)
	const limited = "typesafe-a.json"
	executor := &typesafeCaptureExecutor{statusByAuth: map[string]int{limited: http.StatusTooManyRequests}}
	server.handlers.AuthManager.RegisterExecutor(executor)
	registerTypesafeAuths(t, server, newTypesafeAuth(limited, nil), newTypesafeAuth("typesafe-b.json", nil))

	// Round-robin reaches the rate-limited key within two requests. Both requests must
	// succeed on the other key, and the limited key must be skipped once cooled down.
	for i := 0; i < 2; i++ {
		rr := serveSystemOne(server, `{"model":"jev-latest"}`, nil)
		if rr.Code != http.StatusOK {
			t.Fatalf("request %d status = %d, want 200 from the other key; attempts=%v body=%s", i, rr.Code, executor.authIDs, rr.Body.String())
		}
	}
	limitedAttempts := 0
	for _, id := range executor.authIDs {
		if id == limited {
			limitedAttempts++
		}
	}
	if limitedAttempts != 1 {
		t.Fatalf("rate-limited key attempts = %d, want 1 (cooled down after the 429); attempts=%v", limitedAttempts, executor.authIDs)
	}
	cooled, ok := server.handlers.AuthManager.GetByID(limited)
	if !ok || cooled.NextRetryAfter.IsZero() {
		t.Fatalf("rate-limited key was not cooled down: %+v", cooled)
	}
}

func TestTypesafeSystemOneReturnsLastFailureWhenAllKeysFail(t *testing.T) {
	server := newTestServer(t)
	executor := &typesafeCaptureExecutor{
		statusByAuth: map[string]int{"typesafe-a.json": http.StatusUnauthorized, "typesafe-b.json": http.StatusUnauthorized},
		bodyByAuth:   map[string]string{"typesafe-a.json": `{"detail":"bad key"}`, "typesafe-b.json": `{"detail":"bad key"}`},
	}
	server.handlers.AuthManager.RegisterExecutor(executor)
	registerTypesafeAuths(t, server, newTypesafeAuth("typesafe-a.json", nil), newTypesafeAuth("typesafe-b.json", nil))

	rr := serveSystemOne(server, `{"model":"jev-latest"}`, nil)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want upstream 401; body=%s", rr.Code, rr.Body.String())
	}
	if rr.Body.String() != `{"detail":"bad key"}` {
		t.Fatalf("body = %q, want upstream error", rr.Body.String())
	}
	if len(executor.authIDs) != 2 {
		t.Fatalf("attempts = %v, want each key tried once", executor.authIDs)
	}
}

func TestTypesafeSystemOneDoesNotRotateOnRequestErrors(t *testing.T) {
	server := newTestServer(t)
	executor := &typesafeCaptureExecutor{
		statusByAuth: map[string]int{"typesafe-a.json": http.StatusUnprocessableEntity, "typesafe-b.json": http.StatusUnprocessableEntity},
		bodyByAuth:   map[string]string{"typesafe-a.json": `{"detail":"bad question"}`, "typesafe-b.json": `{"detail":"bad question"}`},
	}
	server.handlers.AuthManager.RegisterExecutor(executor)
	registerTypesafeAuths(t, server, newTypesafeAuth("typesafe-a.json", nil), newTypesafeAuth("typesafe-b.json", nil))

	rr := serveSystemOne(server, `{"model":"jev-latest"}`, nil)

	if rr.Code != http.StatusUnprocessableEntity || rr.Body.String() != `{"detail":"bad question"}` {
		t.Fatalf("status/body = %d %s, want upstream 422 passed through", rr.Code, rr.Body.String())
	}
	if len(executor.authIDs) != 1 {
		t.Fatalf("attempts = %v, want a single attempt", executor.authIDs)
	}
}

func TestTypesafeSystemOneWithoutCredentials(t *testing.T) {
	server := newTestServer(t)
	server.handlers.AuthManager.RegisterExecutor(&typesafeCaptureExecutor{})

	rr := serveSystemOne(server, `{"model":"jev-latest"}`, nil)

	if rr.Code < 400 {
		t.Fatalf("status = %d, want an error without TypeSafe credentials", rr.Code)
	}
}

func TestTypesafeSystemOneRejectsOversizedBody(t *testing.T) {
	server := newTestServer(t)
	executor := &typesafeCaptureExecutor{}
	server.handlers.AuthManager.RegisterExecutor(executor)
	registerTypesafeAuths(t, server, newTypesafeAuth("typesafe-a.json", nil))

	rr := serveSystemOne(server, strings.Repeat("a", typesafeMaxBodyBytes+1), nil)

	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rr.Code)
	}
	if len(executor.authIDs) != 0 {
		t.Fatalf("oversized request reached upstream: %v", executor.authIDs)
	}
}

func TestTypesafeUsageDetail(t *testing.T) {
	detail := typesafeUsageDetail([]byte(`{"usage":{"input_tokens":120,"output_tokens":12}}`))
	if detail.InputTokens != 120 || detail.OutputTokens != 12 || detail.TotalTokens != 132 {
		t.Fatalf("detail = %+v", detail)
	}
	if empty := typesafeUsageDetail([]byte(`not json`)); empty.TotalTokens != 0 {
		t.Fatalf("invalid body detail = %+v, want zero", empty)
	}
}

func TestTypesafeSystemOneClientCancelDoesNotCoolKeys(t *testing.T) {
	server := newTestServer(t)
	executor := &typesafeCaptureExecutor{}
	server.handlers.AuthManager.RegisterExecutor(executor)
	registerTypesafeAuths(t, server, newTypesafeAuth("typesafe-a.json", nil), newTypesafeAuth("typesafe-b.json", nil))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodPost, "/v1/systemone", strings.NewReader(`{"model":"jev-latest"}`)).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer test-key")
	rr := httptest.NewRecorder()
	server.engine.ServeHTTP(rr, req)

	if len(executor.authIDs) != 1 {
		t.Fatalf("attempts = %v, want one attempt before noticing the client left", executor.authIDs)
	}
	for _, id := range []string{"typesafe-a.json", "typesafe-b.json"} {
		if current, ok := server.handlers.AuthManager.GetByID(id); !ok || !current.NextRetryAfter.IsZero() || current.Unavailable {
			t.Fatalf("key %s was penalised for a client disconnect: %+v", id, current)
		}
	}
}

func TestTypesafeSystemOneRotatesPastTransportError(t *testing.T) {
	server := newTestServer(t)
	executor := &typesafeCaptureExecutor{errByAuth: map[string]error{"typesafe-a.json": errors.New("read tcp: connection reset by peer")}}
	server.handlers.AuthManager.RegisterExecutor(executor)
	registerTypesafeAuths(t, server, newTypesafeAuth("typesafe-a.json", nil), newTypesafeAuth("typesafe-b.json", nil))

	for i := 0; i < 2; i++ {
		if rr := serveSystemOne(server, `{"model":"jev-latest"}`, nil); rr.Code != http.StatusOK {
			t.Fatalf("request %d status = %d, want 200 from the healthy key; attempts=%v body=%s", i, rr.Code, executor.authIDs, rr.Body.String())
		}
	}
}
