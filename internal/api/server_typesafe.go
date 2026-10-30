package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/clienterror"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/usage"
	log "github.com/sirupsen/logrus"
)

const (
	// typesafeProvider is the provider key TypeSafe credentials are registered under.
	typesafeProvider = "typesafe"
	// typesafeDefaultBaseURL is used when a credential does not set base_url.
	typesafeDefaultBaseURL = "https://api.typesafe.ai"
	// typesafeMaxBodyBytes mirrors TypeSafe's documented 32 MiB request body cap. Larger
	// upstream responses are refused rather than truncated.
	typesafeMaxBodyBytes = 32 << 20
)

// typesafeSystemOne forwards a TypeSafe System One request (for example to Jev)
// unchanged to a TypeSafe credential. A credential that is rejected, rate limited or
// failing upstream is marked and the request moves on to the next credential.
//
// Like /v1/alpha/search this is a raw pass-through, not a model executor path: the
// body is a typed-decision request, so payload rules are not applied. Home dispatch
// is not supported; SelectAuth reports home_unavailable when Home is enabled.
func (s *Server) typesafeSystemOne(c *gin.Context) {
	if s == nil || s.handlers == nil || s.handlers.AuthManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "TypeSafe auth manager unavailable"})
		return
	}
	manager := s.handlers.AuthManager

	body, errRead := io.ReadAll(io.LimitReader(c.Request.Body, typesafeMaxBodyBytes+1))
	if errRead != nil {
		c.JSON(clienterror.HTTPStatusFromErrorOr(errRead, http.StatusBadRequest), gin.H{"error": "Failed to read System One request"})
		return
	}
	if len(body) > typesafeMaxBodyBytes {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "System One request exceeds 32 MiB"})
		return
	}

	contentEncoding := strings.TrimSpace(c.GetHeader("Content-Encoding"))
	model := ""
	if contentEncoding == "" {
		var routing struct {
			Model string `json:"model"`
		}
		// The model only labels usage records; TypeSafe validates the body itself.
		_ = json.Unmarshal(body, &routing)
		model = strings.TrimSpace(routing.Model)
	}

	headers := make(http.Header)
	contentType := strings.TrimSpace(c.GetHeader("Content-Type"))
	if contentType == "" {
		contentType = "application/json"
	}
	headers.Set("Content-Type", contentType)
	headers.Set("Accept", "application/json")
	if contentEncoding != "" {
		headers.Set("Content-Encoding", contentEncoding)
	}

	ctx := context.WithValue(c.Request.Context(), "gin", c)
	cfg := s.getConfig()
	opts := coreexecutor.Options{Headers: c.Request.Header.Clone(), OriginalRequest: body}
	tried := make(map[string]struct{})
	var last *typesafeUpstreamResult

	for {
		selected, errSelect := manager.SelectAuth(ctx, typesafeProvider, "", opts)
		if errSelect != nil || selected == nil {
			if last != nil {
				break
			}
			if errSelect == nil {
				errSelect = errors.New("no TypeSafe credential available")
			}
			for _, value := range auth.SafeResponseHeaders(errSelect).Values("Retry-After") {
				c.Writer.Header().Add("Retry-After", value)
			}
			c.JSON(clienterror.HTTPStatusFromErrorOr(errSelect, http.StatusServiceUnavailable), gin.H{"error": errSelect.Error()})
			return
		}
		if _, seen := tried[selected.ID]; seen {
			break
		}
		tried[selected.ID] = struct{}{}
		logging.SetGinCPATraceID(c, selected.EnsureIndex())

		result, errAttempt := s.typesafeAttempt(ctx, selected, body, headers)
		reporter := helps.NewUsageReporter(ctx, typesafeProvider, model, selected)
		if errAttempt != nil {
			helps.RecordAPIResponseError(ctx, cfg, errAttempt)
			if errCtx := ctx.Err(); errCtx != nil {
				// The client went away; that says nothing about the credential, and
				// every further attempt would fail the same way.
				c.JSON(clienterror.HTTPStatusFromErrorOr(errCtx, http.StatusRequestTimeout), gin.H{"error": errCtx.Error()})
				return
			}
			reporter.PublishFailure(ctx, errAttempt)
			// Only an explicit status is attached, so the manager can classify
			// transport errors from the message instead of cooling the key as a 5xx.
			attemptErr := &auth.Error{Message: errAttempt.Error()}
			var statusErr interface{ StatusCode() int }
			if errors.As(errAttempt, &statusErr) {
				attemptErr.HTTPStatus = statusErr.StatusCode()
			}
			manager.MarkResult(ctx, auth.Result{
				AuthID:   selected.ID,
				Provider: typesafeProvider,
				Success:  false,
				Error:    attemptErr,
			})
			last = &typesafeUpstreamResult{err: errAttempt}
			continue
		}

		if !typesafeRotatableStatus(result.status) {
			manager.MarkResult(ctx, auth.Result{AuthID: selected.ID, Provider: typesafeProvider, Success: true})
			if result.status >= 200 && result.status < 300 {
				reporter.Publish(ctx, typesafeUsageDetail(result.body))
			}
			last = result
			break
		}

		upstreamErr := &auth.Error{
			Code:       "upstream_status",
			Message:    fmt.Sprintf("TypeSafe returned HTTP %d", result.status),
			Retryable:  true,
			HTTPStatus: result.status,
		}
		reporter.PublishFailure(ctx, upstreamErr)
		manager.MarkResult(ctx, auth.Result{
			AuthID:     selected.ID,
			Provider:   typesafeProvider,
			Success:    false,
			RetryAfter: typesafeRetryAfter(result.headers),
			Error:      upstreamErr,
		})
		log.WithField("status", result.status).Warnf("typesafe system one: credential %s failed: %s", selected.EnsureIndex(), logging.SafeDiagnosticForLog(string(result.body)))
		last = result
	}

	if last.err != nil {
		c.JSON(clienterror.HTTPStatusFromErrorOr(last.err, http.StatusBadGateway), gin.H{"error": last.err.Error()})
		return
	}
	if contentType := last.headers.Get("Content-Type"); contentType != "" {
		c.Header("Content-Type", contentType)
	}
	if retryAfter := last.headers.Get("Retry-After"); retryAfter != "" {
		c.Header("Retry-After", retryAfter)
	}
	c.Status(last.status)
	_, _ = c.Writer.Write(last.body)
}

// typesafeUpstreamResult is one buffered upstream response or the transport error that replaced it.
type typesafeUpstreamResult struct {
	status  int
	headers http.Header
	body    []byte
	err     error
}

// typesafeAttempt sends the System One request through one credential. The TypeSafe
// plugin executor attaches the API key inside HttpRequest; plugin executors do not
// implement request preparation, so the request is built here without it.
func (s *Server) typesafeAttempt(ctx context.Context, selected *auth.Auth, body []byte, headers http.Header) (*typesafeUpstreamResult, error) {
	manager := s.handlers.AuthManager
	cfg := s.getConfig()
	upstreamURL := typesafeBaseURL(selected) + "/v1/systemone"
	req, errRequest := http.NewRequestWithContext(ctx, http.MethodPost, upstreamURL, bytes.NewReader(body))
	if errRequest != nil {
		return nil, errRequest
	}
	req.Header = headers.Clone()
	authType, authValue := selected.AccountInfo()
	helps.RecordAPIRequest(ctx, cfg, helps.UpstreamRequestLog{
		URL:       upstreamURL,
		Method:    http.MethodPost,
		Headers:   req.Header.Clone(),
		Body:      body,
		Provider:  typesafeProvider,
		AuthID:    selected.ID,
		AuthLabel: selected.Label,
		AuthType:  authType,
		AuthValue: authValue,
	})
	resp, errDo := manager.HttpRequest(ctx, selected, req)
	if errDo != nil {
		return nil, errDo
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Errorf("typesafe system one: close response body error: %v", errClose)
		}
	}()
	helps.RecordAPIResponseMetadata(ctx, cfg, resp.StatusCode, resp.Header.Clone())
	respBody, errRead := io.ReadAll(io.LimitReader(resp.Body, typesafeMaxBodyBytes+1))
	helps.AppendAPIResponseChunk(ctx, cfg, respBody)
	if errRead != nil {
		return nil, fmt.Errorf("read TypeSafe response: %w", errRead)
	}
	if len(respBody) > typesafeMaxBodyBytes {
		return nil, errors.New("TypeSafe response exceeds 32 MiB")
	}
	return &typesafeUpstreamResult{status: resp.StatusCode, headers: resp.Header.Clone(), body: respBody}, nil
}

// typesafeBaseURL returns the credential's base URL, defaulting to TypeSafe's API.
func typesafeBaseURL(a *auth.Auth) string {
	baseURL := ""
	if a != nil && a.Attributes != nil {
		baseURL = strings.TrimSpace(a.Attributes["base_url"])
	}
	if baseURL == "" {
		baseURL = typesafeDefaultBaseURL
	}
	return strings.TrimRight(baseURL, "/")
}

// typesafeRotatableStatus reports whether a status belongs to the credential or to
// TypeSafe rather than to the request, so another credential may succeed.
func typesafeRotatableStatus(status int) bool {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests:
		return true
	}
	return status >= http.StatusInternalServerError
}

// typesafeRetryAfter parses a delta-seconds Retry-After header.
func typesafeRetryAfter(headers http.Header) *time.Duration {
	value := strings.TrimSpace(headers.Get("Retry-After"))
	if value == "" {
		return nil
	}
	seconds, errParse := strconv.Atoi(value)
	if errParse != nil || seconds <= 0 {
		return nil
	}
	retryAfter := time.Duration(seconds) * time.Second
	return &retryAfter
}

// typesafeUsageDetail extracts token usage from a System One response.
func typesafeUsageDetail(body []byte) usage.Detail {
	var payload struct {
		Usage struct {
			InputTokens  int64 `json:"input_tokens"`
			OutputTokens int64 `json:"output_tokens"`
		} `json:"usage"`
	}
	if errUnmarshal := json.Unmarshal(body, &payload); errUnmarshal != nil {
		return usage.Detail{}
	}
	return usage.Detail{
		InputTokens:  payload.Usage.InputTokens,
		OutputTokens: payload.Usage.OutputTokens,
		TotalTokens:  payload.Usage.InputTokens + payload.Usage.OutputTokens,
	}
}
