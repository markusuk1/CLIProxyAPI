package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// fakeHost records host.http.do calls and answers with a fixed response.
type fakeHost struct {
	calls    []map[string]any
	response pluginapi.HTTPResponse
}

func (h *fakeHost) call(method string, payload []byte) ([]byte, error) {
	if method != pluginabi.MethodHostHTTPDo {
		return nil, errors.New("unexpected host method " + method)
	}
	var request map[string]any
	if err := json.Unmarshal(payload, &request); err != nil {
		return nil, err
	}
	h.calls = append(h.calls, request)
	result, _ := json.Marshal(h.response)
	return json.Marshal(pluginabi.Envelope{OK: true, Result: result})
}

func call(t *testing.T, p *plugin, method string, request any) pluginabi.Envelope {
	t.Helper()
	payload, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal %s request: %v", method, err)
	}
	var envelope pluginabi.Envelope
	if err := json.Unmarshal(p.handle(method, payload), &envelope); err != nil {
		t.Fatalf("decode %s envelope: %v", method, err)
	}
	return envelope
}

func decodeResult[T any](t *testing.T, envelope pluginabi.Envelope) T {
	t.Helper()
	if !envelope.OK {
		t.Fatalf("call failed: %+v", envelope.Error)
	}
	var result T
	if err := json.Unmarshal(envelope.Result, &result); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	return result
}

func headerValue(t *testing.T, call map[string]any, name string) string {
	t.Helper()
	headers, _ := call["headers"].(map[string]any)
	values, _ := headers[name].([]any)
	if len(values) == 0 {
		return ""
	}
	value, _ := values[0].(string)
	return value
}

const testKey = "ts_live_abcdef1234"

func TestRegisterDeclaresAuthExecutorAndQuota(t *testing.T) {
	result := decodeResult[map[string]any](t, call(t, newPlugin(nil), pluginabi.MethodPluginRegister, map[string]any{}))
	capabilities, _ := result["capabilities"].(map[string]any)
	for _, name := range []string{"auth_provider", "executor", "quota_provider"} {
		if capabilities[name] != true {
			t.Fatalf("capability %s = %v, want true", name, capabilities[name])
		}
	}
	for _, method := range []string{pluginabi.MethodAuthIdentifier, pluginabi.MethodExecutorIdentifier, pluginabi.MethodQuotaIdentifier} {
		identifier := decodeResult[map[string]string](t, call(t, newPlugin(nil), method, map[string]any{}))
		if identifier["identifier"] != providerID {
			t.Fatalf("%s identifier = %q", method, identifier["identifier"])
		}
	}
}

func TestParseAuthAcceptsTypesafeKeyFile(t *testing.T) {
	raw := []byte(`{"type":"TypeSafe","api_key":" ` + testKey + ` "}`)
	resp := decodeResult[pluginapi.AuthParseResponse](t, call(t, newPlugin(nil), pluginabi.MethodAuthParse, pluginapi.AuthParseRequest{FileName: "typesafe-main.json", RawJSON: raw}))
	if !resp.Handled {
		t.Fatal("TypeSafe file was not handled")
	}
	if resp.Auth.Provider != providerID || resp.Auth.ID != "" || resp.Auth.FileName != "typesafe-main.json" {
		t.Fatalf("auth = %+v", resp.Auth)
	}
	if resp.Auth.Label != "TypeSafe key …1234" {
		t.Fatalf("label = %q, want key hint only", resp.Auth.Label)
	}
	if strings.Contains(resp.Auth.Label, testKey) {
		t.Fatal("label exposes the API key")
	}
	if _, ok := resp.Auth.Attributes["base_url"]; ok {
		t.Fatalf("attributes = %v, want default base URL left unset", resp.Auth.Attributes)
	}
}

func TestParseAuthIgnoresOtherProviders(t *testing.T) {
	resp := decodeResult[pluginapi.AuthParseResponse](t, call(t, newPlugin(nil), pluginabi.MethodAuthParse, pluginapi.AuthParseRequest{RawJSON: []byte(`{"type":"codex","access_token":"x"}`)}))
	if resp.Handled {
		t.Fatal("non-TypeSafe file was handled")
	}
}

func TestParseAuthRefusesMalformedTypesafeFiles(t *testing.T) {
	for name, raw := range map[string]string{
		"missing key":  `{"type":"typesafe"}`,
		"http base":    `{"type":"typesafe","api_key":"k","base_url":"http://api.typesafe.ai"}`,
		"relative url": `{"type":"typesafe","api_key":"k","base_url":"api.typesafe.ai"}`,
	} {
		envelope := call(t, newPlugin(nil), pluginabi.MethodAuthParse, pluginapi.AuthParseRequest{RawJSON: []byte(raw)})
		if envelope.OK || envelope.Error == nil || envelope.Error.Code != "invalid_auth" {
			t.Fatalf("%s: envelope = %+v, want invalid_auth error", name, envelope)
		}
	}
}

func TestHTTPRequestAttachesKeyAndCountsUsage(t *testing.T) {
	host := &fakeHost{response: pluginapi.HTTPResponse{
		StatusCode: http.StatusOK,
		Body:       []byte(`{"model":"jev-latest","answers":{},"usage":{"input_tokens":120,"output_tokens":12}}`),
	}}
	p := newPlugin(host.call)
	request := pluginapi.ExecutorHTTPRequest{
		AuthID:      "typesafe-main.json",
		Method:      http.MethodPost,
		URL:         "https://api.typesafe.ai/v1/systemone",
		Headers:     http.Header{"Content-Type": []string{"application/json"}, "Authorization": []string{"Bearer client-key"}},
		Body:        []byte(`{"model":"jev-latest"}`),
		StorageJSON: []byte(`{"type":"typesafe","api_key":"` + testKey + `"}`),
	}

	for i := 0; i < 2; i++ {
		resp := decodeResult[pluginapi.ExecutorHTTPResponse](t, call(t, p, pluginabi.MethodExecutorHTTPRequest, request))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d", resp.StatusCode)
		}
	}

	if len(host.calls) != 2 {
		t.Fatalf("host calls = %d, want 2", len(host.calls))
	}
	if got := headerValue(t, host.calls[0], "Authorization"); got != "Bearer "+testKey {
		t.Fatalf("Authorization = %q, want the TypeSafe key", got)
	}
	if host.calls[0]["url"] != "https://api.typesafe.ai/v1/systemone" {
		t.Fatalf("url = %v", host.calls[0]["url"])
	}
	counts := p.usageFor("typesafe-main.json")
	if counts.requests != 2 || counts.inputTokens != 240 || counts.outputTokens != 24 {
		t.Fatalf("usage = %+v, want 2 requests, 240 in, 24 out", counts)
	}
}

func TestHTTPRequestRefusesForeignHosts(t *testing.T) {
	host := &fakeHost{}
	p := newPlugin(host.call)
	for _, target := range []string{"https://evil.example/v1/systemone", "http://api.typesafe.ai/v1/systemone"} {
		envelope := call(t, p, pluginabi.MethodExecutorHTTPRequest, pluginapi.ExecutorHTTPRequest{
			Method:      http.MethodGet,
			URL:         target,
			StorageJSON: []byte(`{"type":"typesafe","api_key":"` + testKey + `"}`),
		})
		if envelope.OK || envelope.Error == nil || envelope.Error.HTTPStatus != http.StatusForbidden {
			t.Fatalf("%s: envelope = %+v, want 403 refusal", target, envelope)
		}
	}
	if len(host.calls) != 0 {
		t.Fatalf("key was sent to a foreign host: %v", host.calls)
	}
}

func TestHTTPRequestFollowsCredentialBaseURL(t *testing.T) {
	host := &fakeHost{response: pluginapi.HTTPResponse{StatusCode: http.StatusOK, Body: []byte(`{}`)}}
	p := newPlugin(host.call)
	envelope := call(t, p, pluginabi.MethodExecutorHTTPRequest, pluginapi.ExecutorHTTPRequest{
		Method:      http.MethodPost,
		URL:         "https://eu.typesafe.example/v1/systemone",
		StorageJSON: []byte(`{"type":"typesafe","api_key":"` + testKey + `"}`),
		Attributes:  map[string]string{"base_url": "https://eu.typesafe.example"},
	})
	if !envelope.OK {
		t.Fatalf("envelope = %+v, want the credential's own host allowed", envelope.Error)
	}
}

func TestFetchQuotaReportsModelsAndUsage(t *testing.T) {
	host := &fakeHost{response: pluginapi.HTTPResponse{
		StatusCode: http.StatusOK,
		Body:       []byte(`{"models":[{"name":"jev-latest"},{"name":"jev-1.13"}]}`),
	}}
	p := newPlugin(host.call)
	p.record("typesafe-main.json", http.StatusOK, []byte(`{"usage":{"input_tokens":120,"output_tokens":12}}`))

	resp := decodeResult[pluginapi.QuotaFetchResponse](t, call(t, p, pluginabi.MethodQuotaFetch, pluginapi.QuotaFetchRequest{
		AuthID:      "typesafe-main.json",
		Provider:    providerID,
		StorageJSON: []byte(`{"type":"typesafe","api_key":"` + testKey + `"}`),
	}))

	if host.calls[0]["url"] != "https://api.typesafe.ai/v1/models" || host.calls[0]["method"] != http.MethodGet {
		t.Fatalf("quota call = %v", host.calls[0])
	}
	if got := headerValue(t, host.calls[0], "Authorization"); got != "Bearer "+testKey {
		t.Fatalf("Authorization = %q", got)
	}
	want := map[string]float64{"models": 2, "requests": 1, "input_tokens": 120, "output_tokens": 12}
	if len(resp.Summary) != len(want) {
		t.Fatalf("summary = %+v", resp.Summary)
	}
	for _, metric := range resp.Summary {
		if metric.Value != want[metric.Key] || metric.Label == "" {
			t.Fatalf("metric %s = %+v, want value %v", metric.Key, metric, want[metric.Key])
		}
	}
}

func TestFetchQuotaReportsRejectedKey(t *testing.T) {
	host := &fakeHost{response: pluginapi.HTTPResponse{StatusCode: http.StatusUnauthorized, Body: []byte(`{"detail":"invalid key"}`)}}
	envelope := call(t, newPlugin(host.call), pluginabi.MethodQuotaFetch, pluginapi.QuotaFetchRequest{
		StorageJSON: []byte(`{"type":"typesafe","api_key":"` + testKey + `"}`),
	})
	if envelope.OK || envelope.Error == nil || envelope.Error.Code != "key_rejected" || envelope.Error.HTTPStatus != http.StatusUnauthorized {
		t.Fatalf("envelope = %+v, want key_rejected 401", envelope)
	}
}

func TestModelExecutionPointsToSystemOne(t *testing.T) {
	envelope := call(t, newPlugin(nil), pluginabi.MethodExecutorExecute, map[string]any{})
	if envelope.OK || envelope.Error == nil || !strings.Contains(envelope.Error.Message, "/v1/systemone") {
		t.Fatalf("envelope = %+v, want a pointer to /v1/systemone", envelope)
	}
}
