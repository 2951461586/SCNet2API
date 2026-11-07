package server

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
)

// maxBodyBytes 是数据面请求体上限。
const maxBodyBytes = 64 << 20

// writeJSON 输出 JSON。
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

// writeRawJSON 原样输出已编码的 JSON。
func writeRawJSON(w http.ResponseWriter, status int, raw []byte) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(raw)
}

// writeErr 输出统一错误结构。
func writeErr(w http.ResponseWriter, status int, msg, typ string) {
	if typ == "" {
		typ = "invalid_request_error"
	}
	writeJSON(w, status, map[string]any{
		"error": map[string]any{"message": msg, "type": typ},
	})
}

// jsonUnmarshal 是 json.Unmarshal 的薄封装（便于统一替换 / 统计）。
func jsonUnmarshal(raw []byte, v any) error { return json.Unmarshal(raw, v) }

// readBodyWithLimit 读取请求体（超过上限返回错误）。
func readBodyWithLimit(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxBodyBytes {
		return nil, errors.New("请求体过大")
	}
	return raw, nil
}

// isLoopbackAddr 判断远端地址是否来自回环。
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		host = strings.TrimSpace(addr)
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

// hasWildcard 判断 CORS 配置是否含通配。
func hasWildcard(origin string) bool { return strings.Contains(origin, "*") }

// headOf 截取响应开头片段用于排障。
func headOf(raw []byte, n int) string {
	if len(raw) <= n {
		return string(raw)
	}
	return string(raw[:n]) + "…"
}

// estimatePromptLen 估算输入字符数（只统计文本与工具定义）。
func estimatePromptLen(payload map[string]any) int {
	raw, err := json.Marshal(payload)
	if err != nil {
		return 0
	}
	return len(raw)
}

// chatTextLen 统计一次 chat 响应 / chunk 的输出字符数。
func chatTextLen(obj map[string]any) int {
	choices, _ := obj["choices"].([]any)
	total := 0
	for _, c := range choices {
		cm, ok := c.(map[string]any)
		if !ok {
			continue
		}
		if msg, ok := cm["message"].(map[string]any); ok {
			total += contentLen(msg["content"])
			if v, ok := msg["reasoning_content"].(string); ok {
				total += len(v)
			}
			if v, ok := msg["reasoning"].(string); ok {
				total += len(v)
			}
		}
		if delta, ok := cm["delta"].(map[string]any); ok {
			total += contentLen(delta["content"])
			if v, ok := delta["reasoning_content"].(string); ok {
				total += len(v)
			}
			if v, ok := delta["reasoning"].(string); ok {
				total += len(v)
			}
		}
	}
	if v, ok := obj["output_text"].(string); ok {
		total += len(v)
	}
	return total
}

// contentLen 统计 content（字符串或分片数组）的字符数。
func contentLen(v any) int {
	switch t := v.(type) {
	case string:
		return len(t)
	case []any:
		total := 0
		for _, item := range t {
			if m, ok := item.(map[string]any); ok {
				if s, ok := m["text"].(string); ok {
					total += len(s)
				}
			}
		}
		return total
	}
	return 0
}

// requestModelName 读取 payload.model。
func requestModelName(payload map[string]any) string {
	if v, ok := payload["model"].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

// streamFlag 读取 payload.stream。
func streamFlag(payload map[string]any) bool {
	v, _ := payload["stream"].(bool)
	return v
}
