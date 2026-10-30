// Command typesafe is a CLIProxyAPI plugin for TypeSafe System One models such as Jev.
//
// It parses TypeSafe API key auth files, attaches the key to requests the proxy forwards
// to POST /v1/systemone, and reports each key's state as a quota card. Build it as a
// shared library with `go build -buildmode=c-shared`.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

const (
	providerID     = "typesafe"
	pluginVersion  = "1.0.1"
	defaultBaseURL = "https://api.typesafe.ai"
	systemOnePath  = "/v1/systemone"
	modelsPath     = "/v1/models"
)

func main() {}

// hostCaller sends one host callback and returns its raw RPC envelope.
type hostCaller func(method string, payload []byte) ([]byte, error)

// keyUsage counts traffic one API key carried since the plugin was loaded.
type keyUsage struct {
	requests     int64
	inputTokens  int64
	outputTokens int64
}

type plugin struct {
	callHost hostCaller

	mu    sync.Mutex
	usage map[string]*keyUsage
}

func newPlugin(callHost hostCaller) *plugin {
	return &plugin{callHost: callHost, usage: make(map[string]*keyUsage)}
}

// handle serves one plugin RPC and returns its envelope.
func (p *plugin) handle(method string, request []byte) []byte {
	result, errHandle := p.dispatch(method, request)
	if errHandle != nil {
		var rpcErr *pluginabi.Error
		if !errors.As(errHandle, &rpcErr) {
			rpcErr = pluginabi.NewError("plugin_error", errHandle.Error())
		}
		raw, _ := json.Marshal(pluginabi.Envelope{OK: false, Error: rpcErr})
		return raw
	}
	resultJSON, errMarshal := json.Marshal(result)
	if errMarshal != nil {
		raw, _ := pluginabi.NewErrorEnvelope("marshal_failed", errMarshal.Error())
		return raw
	}
	raw, _ := json.Marshal(pluginabi.Envelope{OK: true, Result: resultJSON})
	return raw
}

func (p *plugin) dispatch(method string, request []byte) (any, error) {
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		return registration(), nil
	case pluginabi.MethodPluginQuiesce, pluginabi.MethodPluginShutdown:
		return struct{}{}, nil
	case pluginabi.MethodAuthIdentifier, pluginabi.MethodExecutorIdentifier, pluginabi.MethodQuotaIdentifier:
		return map[string]string{"identifier": providerID}, nil
	case pluginabi.MethodAuthParse:
		return parseAuth(request)
	case pluginabi.MethodAuthRefresh:
		return refreshAuth(request)
	case pluginabi.MethodAuthLoginStart, pluginabi.MethodAuthLoginPoll:
		return nil, pluginabi.NewError("login_unsupported", "TypeSafe uses API keys: add an auth file with type \"typesafe\" and api_key", http.StatusBadRequest)
	case pluginabi.MethodExecutorExecute, pluginabi.MethodExecutorExecuteStream, pluginabi.MethodExecutorCountTokens:
		return nil, pluginabi.NewError("unsupported_endpoint", "TypeSafe models are served at POST /v1/systemone", http.StatusBadRequest)
	case pluginabi.MethodExecutorHTTPRequest:
		return p.httpRequest(request)
	case pluginabi.MethodQuotaDescribe:
		return pluginapi.QuotaDescribeResponse{SupportedProviders: []string{providerID}, DisplayName: "TypeSafe"}, nil
	case pluginabi.MethodQuotaFetch:
		return p.fetchQuota(request)
	case pluginabi.MethodQuotaReset:
		return nil, pluginabi.NewError("reset_unsupported", "TypeSafe has no quota to reset", http.StatusBadRequest)
	default:
		return nil, pluginabi.NewError("unknown_method", "unknown method: "+method)
	}
}

func registration() map[string]any {
	return map[string]any{
		"schema_version": pluginabi.SchemaVersion,
		"metadata": pluginapi.Metadata{
			Name:             providerID,
			Version:          pluginVersion,
			Author:           "markusuk1",
			GitHubRepository: "https://github.com/markusuk1/CLIProxyAPI",
			ConfigFields:     []pluginapi.ConfigField{},
		},
		"capabilities": map[string]any{
			"auth_provider":        true,
			"executor":             true,
			"executor_model_scope": pluginapi.ExecutorModelScopeStatic,
			"quota_provider":       true,
		},
	}
}

// credential is the TypeSafe auth file content.
type credential struct {
	Type     string `json:"type"`
	APIKey   string `json:"api_key"`
	BaseURL  string `json:"base_url"`
	Label    string `json:"label"`
	Disabled bool   `json:"disabled"`
}

func decodeCredential(raw []byte) (credential, error) {
	var cred credential
	if errUnmarshal := json.Unmarshal(raw, &cred); errUnmarshal != nil {
		return credential{}, fmt.Errorf("decode TypeSafe auth: %w", errUnmarshal)
	}
	cred.Type = strings.ToLower(strings.TrimSpace(cred.Type))
	cred.APIKey = strings.TrimSpace(cred.APIKey)
	cred.BaseURL = strings.TrimRight(strings.TrimSpace(cred.BaseURL), "/")
	cred.Label = strings.TrimSpace(cred.Label)
	return cred, nil
}

// validBaseURL refuses anything but an absolute https URL, so the key is never sent in clear.
func validBaseURL(raw string) (*url.URL, error) {
	parsed, errParse := url.Parse(raw)
	if errParse != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return nil, fmt.Errorf("TypeSafe base_url must be an https URL, got %q", raw)
	}
	return parsed, nil
}

func parseAuth(request []byte) (pluginapi.AuthParseResponse, error) {
	var req pluginapi.AuthParseRequest
	if errUnmarshal := json.Unmarshal(request, &req); errUnmarshal != nil {
		return pluginapi.AuthParseResponse{}, fmt.Errorf("decode auth.parse request: %w", errUnmarshal)
	}
	cred, errDecode := decodeCredential(req.RawJSON)
	if errDecode != nil || cred.Type != providerID {
		// Not a TypeSafe file; leave it to other providers.
		return pluginapi.AuthParseResponse{Handled: false}, nil
	}
	data, errData := authData(cred, req.RawJSON, req.FileName)
	if errData != nil {
		return pluginapi.AuthParseResponse{}, errData
	}
	return pluginapi.AuthParseResponse{Handled: true, Auth: data}, nil
}

func refreshAuth(request []byte) (pluginapi.AuthRefreshResponse, error) {
	var req pluginapi.AuthRefreshRequest
	if errUnmarshal := json.Unmarshal(request, &req); errUnmarshal != nil {
		return pluginapi.AuthRefreshResponse{}, fmt.Errorf("decode auth.refresh request: %w", errUnmarshal)
	}
	cred, errDecode := decodeCredential(req.StorageJSON)
	if errDecode != nil {
		return pluginapi.AuthRefreshResponse{}, errDecode
	}
	// API keys do not expire; hand the same auth back.
	data, errData := authData(cred, req.StorageJSON, "")
	if errData != nil {
		return pluginapi.AuthRefreshResponse{}, errData
	}
	data.ID = req.AuthID
	return pluginapi.AuthRefreshResponse{Auth: data}, nil
}

func authData(cred credential, raw []byte, fileName string) (pluginapi.AuthData, error) {
	if cred.APIKey == "" {
		return pluginapi.AuthData{}, pluginabi.NewError("invalid_auth", "TypeSafe auth file has no api_key", http.StatusBadRequest)
	}
	attributes := map[string]string{}
	if cred.BaseURL != "" {
		if _, errURL := validBaseURL(cred.BaseURL); errURL != nil {
			return pluginapi.AuthData{}, pluginabi.NewError("invalid_auth", errURL.Error(), http.StatusBadRequest)
		}
		attributes["base_url"] = cred.BaseURL
	}
	label := cred.Label
	if label == "" {
		label = "TypeSafe key " + keyHint(cred.APIKey)
	}
	// ID stays empty so the host derives its canonical per-path ID; loaders pass
	// file names in different forms, which would otherwise register one key twice.
	return pluginapi.AuthData{
		Provider:    providerID,
		FileName:    fileName,
		Label:       label,
		Disabled:    cred.Disabled,
		StorageJSON: raw,
		Metadata:    map[string]any{"type": providerID},
		Attributes:  attributes,
	}, nil
}

// keyHint shows only the last four characters of a key.
func keyHint(key string) string {
	if len(key) <= 4 {
		return "…"
	}
	return "…" + key[len(key)-4:]
}

// target resolves the key and base URL of one auth and checks a request URL belongs to it.
func target(storageJSON []byte, attributes map[string]string, rawURL string) (string, *url.URL, error) {
	cred, errDecode := decodeCredential(storageJSON)
	if errDecode != nil {
		return "", nil, errDecode
	}
	if cred.APIKey == "" {
		return "", nil, pluginabi.NewError("invalid_auth", "TypeSafe auth has no api_key", http.StatusUnauthorized)
	}
	baseURL := strings.TrimSpace(attributes["base_url"])
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	base, errBase := validBaseURL(baseURL)
	if errBase != nil {
		return "", nil, pluginabi.NewError("invalid_auth", errBase.Error(), http.StatusBadRequest)
	}
	if rawURL == "" {
		return cred.APIKey, base, nil
	}
	requestURL, errURL := url.Parse(rawURL)
	if errURL != nil || requestURL.Scheme != base.Scheme || !strings.EqualFold(requestURL.Host, base.Host) {
		return "", nil, pluginabi.NewError("forbidden_target", "TypeSafe key may only be sent to "+base.Scheme+"://"+base.Host, http.StatusForbidden)
	}
	return cred.APIKey, requestURL, nil
}

type rpcExecutorHTTPRequest struct {
	pluginapi.ExecutorHTTPRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

func (p *plugin) httpRequest(request []byte) (pluginapi.ExecutorHTTPResponse, error) {
	var req rpcExecutorHTTPRequest
	if errUnmarshal := json.Unmarshal(request, &req); errUnmarshal != nil {
		return pluginapi.ExecutorHTTPResponse{}, fmt.Errorf("decode executor.http_request: %w", errUnmarshal)
	}
	key, requestURL, errTarget := target(req.StorageJSON, req.Attributes, req.URL)
	if errTarget != nil {
		return pluginapi.ExecutorHTTPResponse{}, errTarget
	}
	headers := req.Headers.Clone()
	if headers == nil {
		headers = http.Header{}
	}
	headers.Set("Authorization", "Bearer "+key)
	method := req.Method
	if method == "" {
		method = http.MethodPost
	}
	resp, errDo := p.hostHTTP(req.HostCallbackID, method, requestURL.String(), headers, req.Body)
	if errDo != nil {
		return pluginapi.ExecutorHTTPResponse{}, errDo
	}
	if strings.HasSuffix(requestURL.Path, systemOnePath) {
		p.record(req.AuthID, resp.StatusCode, resp.Body)
	}
	return pluginapi.ExecutorHTTPResponse{StatusCode: resp.StatusCode, Headers: resp.Headers, Body: resp.Body}, nil
}

// record counts one System One call against its key.
func (p *plugin) record(authID string, status int, body []byte) {
	var payload struct {
		Usage struct {
			InputTokens  int64 `json:"input_tokens"`
			OutputTokens int64 `json:"output_tokens"`
		} `json:"usage"`
	}
	if status >= 200 && status < 300 {
		_ = json.Unmarshal(body, &payload)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	counts := p.usage[authID]
	if counts == nil {
		counts = &keyUsage{}
		p.usage[authID] = counts
	}
	counts.requests++
	counts.inputTokens += payload.Usage.InputTokens
	counts.outputTokens += payload.Usage.OutputTokens
}

func (p *plugin) usageFor(authID string) keyUsage {
	p.mu.Lock()
	defer p.mu.Unlock()
	if counts := p.usage[authID]; counts != nil {
		return *counts
	}
	return keyUsage{}
}

type rpcQuotaFetchRequest struct {
	pluginapi.QuotaFetchRequest
	HostCallbackID string `json:"host_callback_id,omitempty"`
}

func (p *plugin) fetchQuota(request []byte) (pluginapi.QuotaFetchResponse, error) {
	var req rpcQuotaFetchRequest
	if errUnmarshal := json.Unmarshal(request, &req); errUnmarshal != nil {
		return pluginapi.QuotaFetchResponse{}, fmt.Errorf("decode quota.fetch request: %w", errUnmarshal)
	}
	key, base, errTarget := target(req.StorageJSON, req.Attributes, "")
	if errTarget != nil {
		return pluginapi.QuotaFetchResponse{}, errTarget
	}
	modelsURL := strings.TrimRight(base.String(), "/") + modelsPath
	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+key)
	headers.Set("Accept", "application/json")
	resp, errDo := p.hostHTTP(req.HostCallbackID, http.MethodGet, modelsURL, headers, nil)
	if errDo != nil {
		return pluginapi.QuotaFetchResponse{}, errDo
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return pluginapi.QuotaFetchResponse{}, statusError(resp.StatusCode)
	}
	var list struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	if errUnmarshal := json.Unmarshal(resp.Body, &list); errUnmarshal != nil {
		return pluginapi.QuotaFetchResponse{}, pluginabi.NewError("invalid_response", "TypeSafe returned an unreadable model list", http.StatusBadGateway)
	}
	counts := p.usageFor(req.AuthID)
	return pluginapi.QuotaFetchResponse{
		Summary: []pluginapi.QuotaMetric{
			{Key: "models", Label: "Models", Value: float64(len(list.Models))},
			{Key: "requests", Label: "Requests since restart", Value: float64(counts.requests)},
			{Key: "input_tokens", Label: "Input tokens since restart", Value: float64(counts.inputTokens)},
			{Key: "output_tokens", Label: "Output tokens since restart", Value: float64(counts.outputTokens)},
		},
	}, nil
}

func statusError(status int) error {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return pluginabi.NewError("key_rejected", fmt.Sprintf("TypeSafe rejected the API key (HTTP %d)", status), status)
	case http.StatusTooManyRequests:
		return pluginabi.NewError("rate_limited", "TypeSafe is rate limiting this key (HTTP 429)", status)
	default:
		return pluginabi.NewError("upstream_error", fmt.Sprintf("TypeSafe returned HTTP %d", status), http.StatusBadGateway)
	}
}

// hostHTTP sends an upstream request through the host so its proxy and logging apply.
func (p *plugin) hostHTTP(callbackID, method, rawURL string, headers http.Header, body []byte) (pluginapi.HTTPResponse, error) {
	if p.callHost == nil {
		return pluginapi.HTTPResponse{}, errors.New("host callbacks unavailable")
	}
	payload, errMarshal := json.Marshal(map[string]any{
		"host_callback_id": callbackID,
		"method":           method,
		"url":              rawURL,
		"headers":          headers,
		"body":             body,
	})
	if errMarshal != nil {
		return pluginapi.HTTPResponse{}, errMarshal
	}
	raw, errCall := p.callHost(pluginabi.MethodHostHTTPDo, payload)
	if errCall != nil {
		return pluginapi.HTTPResponse{}, errCall
	}
	var envelope pluginabi.Envelope
	if errUnmarshal := json.Unmarshal(raw, &envelope); errUnmarshal != nil {
		return pluginapi.HTTPResponse{}, fmt.Errorf("decode host.http.do response: %w", errUnmarshal)
	}
	if !envelope.OK {
		if envelope.Error != nil {
			return pluginapi.HTTPResponse{}, envelope.Error
		}
		return pluginapi.HTTPResponse{}, errors.New("host.http.do failed")
	}
	var resp pluginapi.HTTPResponse
	if errUnmarshal := json.Unmarshal(envelope.Result, &resp); errUnmarshal != nil {
		return pluginapi.HTTPResponse{}, fmt.Errorf("decode host.http.do result: %w", errUnmarshal)
	}
	return resp, nil
}
