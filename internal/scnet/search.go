package scnet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// SearchRequest 是联网搜索请求。
type SearchRequest struct {
	Query     string `json:"query"`
	Count     int    `json:"count,omitempty"`
	Freshness string `json:"freshness,omitempty"` // noLimit / oneDay / oneWeek / oneMonth / oneYear
	Summary   bool   `json:"summary,omitempty"`
}

// SearchItem 是一条搜索结果。
type SearchItem struct {
	Title     string `json:"title,omitempty"`
	URL       string `json:"url,omitempty"`
	Snippet   string `json:"snippet,omitempty"`
	Summary   string `json:"summary,omitempty"`
	SiteName  string `json:"siteName,omitempty"`
	SiteIcon  string `json:"siteIcon,omitempty"`
	Published string `json:"published,omitempty"`
}

// SearchResult 是联网搜索的归一化结果。
type SearchResult struct {
	Query  string       `json:"query"`
	Engine string       `json:"engine,omitempty"`
	Total  int          `json:"total,omitempty"`
	Items  []SearchItem `json:"items"`
}

// Search 调用上游联网搜索（需要 MCP Key）。
//
// 上游：POST https://api.scnet.cn/api/llm/web-search
// 鉴权：Authorization: Bearer <mcp-key>
// 响应形如 data.data.webPages.value[]，本方法会把常见嵌套都归一化。
func (c *Client) Search(ctx context.Context, searchKey string, req SearchRequest) (*SearchResult, error) {
	searchKey = strings.TrimSpace(searchKey)
	if searchKey == "" {
		return nil, fmt.Errorf("联网搜索凭据不可用")
	}
	query := strings.TrimSpace(req.Query)
	if query == "" {
		return nil, fmt.Errorf("query 不能为空")
	}
	if req.Count <= 0 {
		req.Count = 10
	}
	if req.Count > 50 {
		req.Count = 50
	}
	if req.Freshness == "" {
		req.Freshness = "noLimit"
	}
	payload := map[string]any{
		"query":     query,
		"count":     req.Count,
		"freshness": req.Freshness,
		"summary":   req.Summary,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	u := c.APIOrigin + WebSearchPath
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+searchKey)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	if c.UserAgent != "" {
		httpReq.Header.Set("User-Agent", c.UserAgent)
	}
	resp, err := c.HTTP.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("联网搜索请求失败: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, &HTTPError{Op: "联网搜索", Status: resp.StatusCode, Body: raw}
	}

	var envelope map[string]any
	if err := DecodeJSON(raw, &envelope); err != nil {
		return nil, fmt.Errorf("联网搜索响应解析失败: %w", err)
	}
	if code := str(envelope["code"]); code != "" && code != "0" && code != "200" {
		return nil, &ProviderError{Op: "联网搜索", Code: code, Msg: firstNonEmpty(str(envelope["msg"]), "上游返回失败")}
	}
	pages := findWebPages(envelope)
	if pages == nil {
		return nil, fmt.Errorf("联网搜索响应结构异常")
	}
	out := &SearchResult{Query: query, Engine: "bocha", Total: intValue(pages["totalEstimatedMatches"], 0)}
	values, _ := pages["value"].([]any)
	for _, item := range values {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		si := SearchItem{
			Title:     firstNonEmpty(str(m["name"]), str(m["title"])),
			URL:       str(m["url"]),
			Snippet:   str(m["snippet"]),
			Summary:   str(m["summary"]),
			SiteName:  str(m["siteName"]),
			SiteIcon:  str(m["siteIcon"]),
			Published: firstNonEmpty(str(m["datePublished"]), str(m["dateLastCrawled"])),
		}
		if si.URL == "" && si.Title == "" && si.Snippet == "" && si.Summary == "" {
			continue
		}
		out.Items = append(out.Items, si)
		if len(out.Items) >= req.Count {
			break
		}
	}
	return out, nil
}

// findWebPages 在嵌套响应里定位 webPages 对象。
func findWebPages(v any) map[string]any {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	if pages, ok := m["webPages"].(map[string]any); ok {
		return pages
	}
	for _, key := range []string{"data", "result", "results", "payload"} {
		if next, ok := m[key]; ok {
			if pages := findWebPages(next); pages != nil {
				return pages
			}
		}
	}
	return nil
}
