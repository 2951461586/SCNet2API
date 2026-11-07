package scnet

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Client 是 SCNet 上游客户端（协议层，可安全并发复用）。
type Client struct {
	WebOrigin string
	APIOrigin string
	HTTP      *http.Client
	UserAgent string
	Version   string
	Source    string

	mu      sync.Mutex
	clients map[string]*http.Client // 按代理串复用 Transport
}

// NewClient 构造默认客户端（遵循环境代理）。
func NewClient() *Client {
	return NewClientWithProxy("")
}

// NewClientWithProxy 构造走指定代理的客户端。
func NewClientWithProxy(proxyRaw string) *Client {
	return &Client{
		WebOrigin: strings.TrimRight(EnvOr("SCNET2API_WEB_ORIGIN", WebOrigin), "/"),
		APIOrigin: strings.TrimRight(EnvOr("SCNET2API_API_ORIGIN", APIOrigin), "/"),
		HTTP:      newHTTPClient(proxyRaw),
		UserAgent: EnvOr("SCNET2API_USER_AGENT", "scnet-client/4.1.0"),
		Version:   EnvOr("SCNET2API_CLIENT_VERSION", "4.1.0"),
		Source:    "Electron",
		clients:   map[string]*http.Client{},
	}
}

// ForProxy 返回使用指定代理的派生客户端（空代理返回自身）。
func (c *Client) ForProxy(proxyRaw string) *Client {
	proxyRaw = strings.TrimSpace(proxyRaw)
	if proxyRaw == "" {
		return c
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	hc, ok := c.clients[proxyRaw]
	if !ok {
		hc = newHTTPClient(proxyRaw)
		c.clients[proxyRaw] = hc
	}
	return &Client{
		WebOrigin: c.WebOrigin,
		APIOrigin: c.APIOrigin,
		HTTP:      hc,
		UserAgent: c.UserAgent,
		Version:   c.Version,
		Source:    c.Source,
		clients:   map[string]*http.Client{},
	}
}

func newHTTPClient(proxyRaw string) *http.Client {
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: 2 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	if u := ParseProxy(proxyRaw); u != nil {
		transport.Proxy = http.ProxyURL(u)
	}
	return &http.Client{Transport: transport}
}

// --- 平台面（会话鉴权） ---

// envelope 是平台面的统一响应包装。
type envelope struct {
	Code any             `json:"code"`
	Msg  string          `json:"msg"`
	Data json.RawMessage `json:"data"`
}

// LoginToken 用桌面端保存的 desktopToken 换取平台会话。
//
// 上游接口：POST /ac/api/auth/loginDesktopClientByToken.action
// 表单字段：desktopToken / sensors_anon_id。
// 返回 Cookie（Token=<uuid>; jsessionid=…）与 X-Jwt-Access-Token。
func (c *Client) LoginToken(ctx context.Context, desktopToken string) (*Session, error) {
	desktopToken = strings.TrimSpace(desktopToken)
	if desktopToken == "" {
		return nil, errors.New("desktopToken 不能为空")
	}
	form := url.Values{}
	form.Set("desktopToken", desktopToken)
	form.Set("sensors_anon_id", "")
	resp, body, err := c.postForm(ctx, "/ac/api/auth/loginDesktopClientByToken.action", form, "")
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, &HTTPError{Op: "SCNet 登录", Status: resp.StatusCode, Body: body}
	}
	return parseLoginEnvelope("SCNet 登录", resp, body, desktopToken)
}

// cookieHeader 从 Set-Cookie 中提取 Token 与 jsessionid。
//
// 不能只保留 Token：某些网关会同时校验 jsessionid；
// 顺序固定为 jsessionid 在前，便于日志比对。
func cookieHeader(resp *http.Response) string {
	var token, jsession string
	for _, ck := range resp.Cookies() {
		switch ck.Name {
		case "Token":
			token = ck.Value
		case "jsessionid":
			jsession = ck.Value
		}
	}
	var parts []string
	if jsession != "" {
		parts = append(parts, "jsessionid="+jsession)
	}
	if token != "" {
		parts = append(parts, "Token="+token)
	}
	return strings.Join(parts, "; ")
}

// acxRequest 发起一次平台面（/acx）JSON 请求。
func (c *Client) acxRequest(ctx context.Context, sess *Session, method, path string, query url.Values, payload any) (json.RawMessage, error) {
	if sess == nil || sess.Cookie == "" || sess.AccessJWT == "" {
		return nil, &HTTPError{Op: "SCNet 平台请求", Status: http.StatusUnauthorized,
			Body: []byte(`{"code":"401","msg":"会话不可用"}`)}
	}
	u := c.WebOrigin + "/acx" + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var body io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Cookie", sess.Cookie)
	req.Header.Set("token", sess.AccessJWT)
	req.Header.Set("source", c.Source)
	req.Header.Set("version", c.Version)
	req.Header.Set("User-Agent", c.UserAgent)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("SCNet 平台请求失败: %w", err)
	}
	defer resp.Body.Close()
	raw, err := LimitReader(resp.Body, maxJSONBytes)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, &HTTPError{Op: "SCNet 平台请求", Status: resp.StatusCode, Body: raw}
	}
	var env envelope
	if err := DecodeJSON(raw, &env); err != nil {
		return nil, &HTTPError{Op: "SCNet 平台请求", Status: resp.StatusCode, Body: raw}
	}
	if code := anyString(env.Code); code != "0" && code != "" {
		// 平台面的 401 常见于 code=401 / 1015。
		he := &HTTPError{Op: "SCNet 平台请求", Status: resp.StatusCode, Body: raw}
		if code == "401" || code == "1015" {
			he.Status = http.StatusUnauthorized
		}
		return nil, he
	}
	return env.Data, nil
}

// ACX 暴露平台面调用（供上层做账号探测 / 凭据管理）。
func (c *Client) ACX(ctx context.Context, sess *Session, method, path string, payload any) (json.RawMessage, error) {
	return c.acxRequest(ctx, sess, method, path, nil, payload)
}

// ACXQuery 带查询参数的平台面调用。
func (c *Client) ACXQuery(ctx context.Context, sess *Session, method, path string, query url.Values, payload any) (json.RawMessage, error) {
	return c.acxRequest(ctx, sess, method, path, query, payload)
}
