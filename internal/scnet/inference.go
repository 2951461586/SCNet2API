package scnet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Protocol 是模型网关支持的三类协议。
type Protocol string

const (
	// ProtoChat 是 OpenAI Chat Completions。
	ProtoChat Protocol = "chat"
	// ProtoResponses 是 OpenAI Responses。
	ProtoResponses Protocol = "responses"
	// ProtoAnthropic 是 Anthropic Messages。
	ProtoAnthropic Protocol = "anthropic"
)

// LLMRequest 发起一次模型网关请求（API Key 鉴权）。
//
// extra 中的头会覆盖默认值（例如客户端传入的 anthropic-version）。
func (c *Client) LLMRequest(ctx context.Context, cred *Credential, method, path string, body []byte, extra http.Header) (*http.Response, error) {
	if cred == nil || cred.APIKey == "" {
		return nil, fmt.Errorf("模型凭据不可用，请先刷新账号")
	}
	url := strings.TrimRight(cred.BaseURL, "/") + path
	var reader *bytes.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+cred.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	for k, values := range extra {
		for _, v := range values {
			req.Header.Set(k, v)
		}
	}
	return c.HTTP.Do(req)
}

// Chat 发起 OpenAI Chat Completions 请求。
func (c *Client) Chat(ctx context.Context, cred *Credential, body []byte, extra http.Header) (*http.Response, error) {
	return c.LLMRequest(ctx, cred, http.MethodPost, "/chat/completions", body, extra)
}

// Responses 发起 OpenAI Responses 请求。
func (c *Client) Responses(ctx context.Context, cred *Credential, body []byte, extra http.Header) (*http.Response, error) {
	return c.LLMRequest(ctx, cred, http.MethodPost, "/responses", body, extra)
}

// Messages 发起 Anthropic Messages 请求。
func (c *Client) Messages(ctx context.Context, cred *Credential, body []byte, extra http.Header) (*http.Response, error) {
	if cred.AnthropicBaseURL == "" {
		return nil, fmt.Errorf("账号缺少 Anthropic 基地址")
	}
	cp := *cred
	cp.BaseURL = cred.AnthropicBaseURL
	h := http.Header{}
	for k, v := range extra {
		h[k] = v
	}
	h.Set("x-api-key", cred.APIKey)
	if h.Get("anthropic-version") == "" {
		h.Set("anthropic-version", "2023-06-01")
	}
	return c.LLMRequest(ctx, &cp, http.MethodPost, "/v1/messages", body, h)
}

// ParseUsage 从 OpenAI / Anthropic 响应中解析 token 用量。
func ParseUsage(raw json.RawMessage) (in, out int) {
	var payload struct {
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
			InputTokens      int `json:"input_tokens"`
			OutputTokens     int `json:"output_tokens"`
		} `json:"usage"`
	}
	if DecodeJSON(raw, &payload) != nil {
		return 0, 0
	}
	in = payload.Usage.PromptTokens
	if in == 0 {
		in = payload.Usage.InputTokens
	}
	out = payload.Usage.CompletionTokens
	if out == 0 {
		out = payload.Usage.OutputTokens
	}
	return in, out
}
