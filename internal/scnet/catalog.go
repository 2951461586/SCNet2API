package scnet

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// rawModel 是 /llm/api/console/model 的原始条目（只保留需要的字段）。
type rawModel struct {
	ModelName   string           `json:"modelName"`
	DisplayName string           `json:"displayName"`
	ModelType   string           `json:"modelType"`
	MaxToken    any              `json:"maxToken"`
	Brand       string           `json:"brand"`
	Description string           `json:"description"`
	ShortDesc   string           `json:"shortDescription"`
	PriceLabel  string           `json:"priceLabel"`
	LogoURL     string           `json:"logoUrl"`
	Visibility  any              `json:"visibility"`
	Disabled    bool             `json:"disabled"`
	Tags        []map[string]any `json:"tags"`
	Protocols   []map[string]any `json:"protocols"`
	Modalities  struct {
		Input  []string `json:"input"`
		Output []string `json:"output"`
	} `json:"modalities"`
	ChatModelID any `json:"chatModelId"`
}

// FetchModels 拉取模型目录（仅 LLM 类型）。
//
// 目录接口在平台面：GET /acx/llm/api/console/model。
// maxToken 的单位是 KiB（桌面端按 ×1024 换算上下文窗口）。
func (c *Client) FetchModels(ctx context.Context, sess *Session) ([]Model, error) {
	raw, err := c.ACX(ctx, sess, "GET", "/llm/api/console/model", nil)
	if err != nil {
		return nil, err
	}
	var rows []rawModel
	if err := DecodeJSON(raw, &rows); err != nil {
		// 兼容 {records:[…]} / {data:[…]} 等包装。
		var wrapper map[string]json.RawMessage
		if err2 := DecodeJSON(raw, &wrapper); err2 != nil {
			return nil, fmt.Errorf("模型目录解析失败: %w", err)
		}
		for _, key := range []string{"data", "records", "list", "models"} {
			if inner, ok := wrapper[key]; ok {
				if err3 := DecodeJSON(inner, &rows); err3 == nil {
					break
				}
			}
		}
	}
	now := time.Now().Unix()
	out := make([]Model, 0, len(rows))
	for _, r := range rows {
		if !strings.EqualFold(strings.TrimSpace(r.ModelType), "LLM") {
			continue
		}
		id := strings.TrimSpace(r.ModelName)
		if id == "" || r.Disabled {
			continue
		}
		if v := anyString(r.Visibility); v == "0" {
			// visibility=0 表示未上架。
			continue
		}
		m := Model{
			ID:            id,
			Name:          firstNonEmpty(r.DisplayName, id),
			Brand:         r.Brand,
			Description:   firstNonEmpty(r.Description, r.ShortDesc),
			ContextWindow: contextWindowOf(id, r.MaxToken),
			MaxTokens:     131072,
			PriceLabel:    strings.ToLower(r.PriceLabel),
			UpdatedAt:     now,
		}
		m.Free = m.PriceLabel == "free"
		for _, t := range r.Tags {
			code := str(t["code"])
			if code != "" {
				m.Tags = append(m.Tags, code)
			}
			if strings.EqualFold(code, "deep_reasoning") {
				m.Reasoning = true
			}
		}
		for _, p := range r.Protocols {
			if code := str(p["code"]); code != "" {
				m.Protocols = append(m.Protocols, strings.ToUpper(code))
			}
		}
		m.Input = []string{"text"}
		for _, in := range r.Modalities.Input {
			if strings.EqualFold(in, "IMAGE") || strings.EqualFold(in, "image") {
				m.Input = append(m.Input, "image")
				break
			}
		}
		if len(m.Input) == 1 {
			for _, t := range m.Tags {
				if t == "vision_understanding" {
					m.Input = append(m.Input, "image")
					break
				}
			}
		}
		if len(m.Protocols) == 0 {
			m.Protocols = []string{"OPENAI_CHAT"}
		}
		out = append(out, m)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("上游模型目录为空")
	}
	return out, nil
}

// contextWindowOf 把 maxToken（KiB）换算为上下文窗口。
func contextWindowOf(id string, maxToken any) int {
	n := intValue(maxToken, 0)
	if n <= 0 {
		return 1048576
	}
	return n * 1024
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// ListRemoteModels 返回模型网关侧的模型 ID 列表（需要有效 API Key）。
//
// 用于验活：能拿到列表说明 Key 可被模型网关接受。
func (c *Client) ListRemoteModels(ctx context.Context, cred *Credential) ([]string, error) {
	if cred == nil || cred.APIKey == "" {
		return nil, fmt.Errorf("模型凭据不可用")
	}
	resp, err := c.LLMRequest(ctx, cred, "GET", "/models", nil, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := LimitReader(resp.Body, maxJSONBytes)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, &HTTPError{Op: "模型目录", Status: resp.StatusCode, Body: raw}
	}
	var payload struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := DecodeJSON(raw, &payload); err != nil {
		return nil, fmt.Errorf("模型目录解析失败: %w", err)
	}
	out := make([]string, 0, len(payload.Data))
	for _, m := range payload.Data {
		if m.ID != "" {
			out = append(out, m.ID)
		}
	}
	return out, nil
}
