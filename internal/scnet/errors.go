package scnet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// HTTPError 是上游返回的非 2xx 响应。
type HTTPError struct {
	Op     string
	Status int
	Body   []byte
}

// Error 返回可读错误信息（优先使用上游 message/msg/error.message）。
func (e *HTTPError) Error() string {
	if msg := upstreamMessage(e.Body); msg != "" {
		return fmt.Sprintf("%s: %s", e.Op, msg)
	}
	body := strings.TrimSpace(string(e.Body))
	if len(body) > 200 {
		body = body[:200] + "…"
	}
	if body == "" {
		return fmt.Sprintf("%s: HTTP %d", e.Op, e.Status)
	}
	return fmt.Sprintf("%s: HTTP %d: %s", e.Op, e.Status, body)
}

// Code 返回上游错误码（平台面 code / 模型面 error.code）。
func (e *HTTPError) Code() string {
	return upstreamCode(e.Body)
}

// Retryable 报告该错误是否值得换账号 / 重试。
func (e *HTTPError) Retryable() bool {
	switch e.Status {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusRequestTimeout,
		http.StatusConflict, http.StatusTooManyRequests, http.StatusInternalServerError,
		http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return e.Status >= 500
}

// AuthFailed 报告是否为账号鉴权失败。
func (e *HTTPError) AuthFailed() bool {
	return e.Status == http.StatusUnauthorized || e.Status == http.StatusForbidden
}

// BalanceExhausted 报告是否为余额不足（402 Insufficient Balance）。
func (e *HTTPError) BalanceExhausted() bool {
	if e.Status == http.StatusPaymentRequired {
		return true
	}
	msg := strings.ToLower(upstreamMessage(e.Body))
	return strings.Contains(msg, "insufficient balance") || strings.Contains(msg, "余额不足")
}

// ModelUnsupported 报告是否为模型 / 协议不支持。
func (e *HTTPError) ModelUnsupported() bool {
	if e.Status != http.StatusBadRequest && e.Status != http.StatusNotFound {
		return false
	}
	msg := strings.ToLower(upstreamMessage(e.Body))
	for _, marker := range []string{"model not found", "model_not_found", "unsupported model", "does not support"} {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

// upstreamMessage 从平台面 / 模型面两种错误结构里取 message。
func upstreamMessage(body []byte) string {
	var payload struct {
		Msg     string `json:"msg"`
		Message string `json:"message"`
		Error   struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if DecodeJSON(body, &payload) != nil {
		return ""
	}
	for _, s := range []string{payload.Error.Message, payload.Msg, payload.Message} {
		if strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

// upstreamCode 从两种错误结构里取 code。
func upstreamCode(body []byte) string {
	var payload struct {
		Code  any `json:"code"`
		Error struct {
			Code any `json:"code"`
		} `json:"error"`
	}
	if DecodeJSON(body, &payload) != nil {
		return ""
	}
	if s := anyString(payload.Error.Code); s != "" {
		return s
	}
	return anyString(payload.Code)
}

func anyString(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case float64:
		return fmt.Sprintf("%.0f", t)
	case json.Number:
		return t.String()
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", t)
	}
}

// transientMarkers 是已知的“出口 / 网络抖动”错误特征。
var transientMarkers = []string{
	"no exit node",
	"unexpected eof",
	"tls handshake timeout",
	"connection reset",
	"connection refused",
	"broken pipe",
	"i/o timeout",
	"timeout awaiting response",
	"temporary failure in name resolution",
	"stream error",
}

// IsTransient 报告错误是否属于“再试一次可能成功”的瞬时故障。
func IsTransient(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) {
		return false
	}
	var he *HTTPError
	if errors.As(err, &he) {
		switch he.Status {
		case http.StatusRequestTimeout, http.StatusTooEarly, http.StatusTooManyRequests:
			return true
		}
		return he.Status >= 500
	}
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	msg := strings.ToLower(err.Error())
	for _, marker := range transientMarkers {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

// RetryAfter 解析 Retry-After 头（秒），上限 30s。
func RetryAfter(resp *http.Response, fallback time.Duration) time.Duration {
	if resp == nil {
		return fallback
	}
	raw := strings.TrimSpace(resp.Header.Get("Retry-After"))
	if raw == "" {
		return fallback
	}
	var secs int
	if _, err := fmt.Sscanf(raw, "%d", &secs); err != nil || secs <= 0 {
		return fallback
	}
	if secs > 30 {
		secs = 30
	}
	return time.Duration(secs) * time.Second
}
