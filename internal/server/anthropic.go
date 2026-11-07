package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"scnet2api/internal/scnet"
)

// handleAnthropicMessages 把 /v1/messages 透传到上游 Anthropic 兼容端。
//
// SCNet 模型网关本身提供 Anthropic Messages 协议（/api/llm/anthropic/v1/messages），
// 因此这里只做模型名改写、鉴权注入、流式转发与用量统计，不做协议翻译——
// 这样 tool_use / thinking / cache 等细节都由上游原生支持。
func (s *Server) handleAnthropicMessages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAnthropicErr(w, http.StatusMethodNotAllowed, "invalid_request_error", "仅支持 POST")
		return
	}
	start := time.Now()

	raw, err := readBodyWithLimit(w, r)
	if err != nil {
		writeAnthropicErr(w, http.StatusRequestEntityTooLarge, "invalid_request_error", "请求体过大")
		return
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		writeAnthropicErr(w, http.StatusBadRequest, "invalid_request_error", "请求体解析失败: "+err.Error())
		return
	}
	if msgs, ok := payload["messages"].([]any); !ok || len(msgs) == 0 {
		writeAnthropicErr(w, http.StatusBadRequest, "invalid_request_error", "messages 不能为空")
		return
	}

	model := s.resolveModel(requestModelName(payload))
	if len(model.Protocols) > 0 && !model.Supports("ANTHROPIC") {
		writeAnthropicErr(w, http.StatusBadRequest, "invalid_request_error",
			"模型 "+model.ID+" 不支持 Anthropic 协议，请换用支持该协议的模型")
		return
	}
	payload["model"] = model.ID
	stream := streamFlag(payload)
	payload["stream"] = stream

	body, err := json.Marshal(payload)
	if err != nil {
		writeAnthropicErr(w, http.StatusBadRequest, "invalid_request_error", "请求序列化失败")
		return
	}
	key := extractKey(r)
	promptLen := estimatePromptLen(payload)

	ctx := r.Context()
	if !stream {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, nonStreamBudget)
		defer cancel()
	}
	header := http.Header{}
	for _, name := range []string{"anthropic-version", "anthropic-beta"} {
		if v := r.Header.Get(name); v != "" {
			header.Set(name, v)
		}
	}
	resp, acct, err := s.openLLM(ctx, llmCall{
		Proto: scnet.ProtoAnthropic, Path: "/v1/messages", Body: body, Header: header,
		Group: s.requestGroup(r), PreferPaid: !model.IsFree(),
	})
	rl := s.newReqLog(key, acctLabel(acct), model.ID, "messages", stream, start, promptLen)
	if err != nil {
		rl.done(0, 0, 0, 0, err)
		writeAnthropicUpstreamErr(w, err)
		return
	}
	defer resp.Body.Close()

	if stream {
		s.streamAnthropic(w, resp.Body, rl)
		return
	}
	rawResp, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		rl.done(0, 0, 0, 0, err)
		writeAnthropicErr(w, http.StatusBadGateway, "api_error", "读取上游响应失败")
		return
	}
	var out map[string]any
	if err := json.Unmarshal(rawResp, &out); err != nil {
		rl.done(0, 0, 0, 0, err)
		writeAnthropicErr(w, http.StatusBadGateway, "api_error", "上游响应不是合法 JSON")
		return
	}
	if model.ID != "" {
		out["model"] = model.ID
	}
	in, outTokens := anthropicUsage(out)
	outLen := anthropicTextLen(out)
	rl.done(http.StatusOK, outLen, in, outTokens, nil)
	writeRawJSON(w, http.StatusOK, rawResp)
}

// streamAnthropic 原样透传 Anthropic SSE（event: + data:）。
func (s *Server) streamAnthropic(w http.ResponseWriter, body io.Reader, rl *reqLog) {
	sw := newSSEWriter(w)
	sw.start()

	var outLen, tokensIn, tokensOut int
	streamErr := scnet.ForEachSSEFrame(body, func(f scnet.SSEFrame) bool {
		if f.Comment != "" {
			sw.comment(f.Comment)
			return true
		}
		if f.Object == nil {
			if f.Data != "" {
				sw.event(f.Event, []byte(f.Data))
			}
			return true
		}
		name := f.Event
		if name == "" {
			if v, ok := f.Object["type"].(string); ok {
				name = v
			}
		}
		if name == "message_start" {
			if msg, ok := f.Object["message"].(map[string]any); ok {
				msg["model"] = rl.model
			}
		}
		c, r := scnet.AnthropicDelta(f.Object)
		outLen += len(c) + len(r)
		if u, ok := f.Object["usage"].(map[string]any); ok {
			if v, ok := u["input_tokens"].(float64); ok && v > 0 {
				tokensIn = int(v)
			}
			if v, ok := u["output_tokens"].(float64); ok && v > 0 {
				tokensOut = int(v)
			}
		}
		tokensIn = maxInt(tokensIn, scnet.ParseAnthropicInput(f.Object))
		raw, _ := json.Marshal(f.Object)
		sw.event(name, raw)
		return true
	})
	if streamErr != nil {
		raw, _ := json.Marshal(map[string]any{
			"type":  "error",
			"error": map[string]any{"type": "api_error", "message": streamErr.Error()},
		})
		sw.event("error", raw)
	}
	rl.done(http.StatusOK, outLen, tokensIn, tokensOut, streamErr)
}

// handleAnthropicCountTokens 本地估算 token 数（上游不提供该接口）。
func (s *Server) handleAnthropicCountTokens(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAnthropicErr(w, http.StatusMethodNotAllowed, "invalid_request_error", "仅支持 POST")
		return
	}
	raw, err := readBodyWithLimit(w, r)
	if err != nil {
		writeAnthropicErr(w, http.StatusBadRequest, "invalid_request_error", "请求体过大")
		return
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		writeAnthropicErr(w, http.StatusBadRequest, "invalid_request_error", "请求体解析失败")
		return
	}
	chars := estimatePromptLen(payload)
	writeJSON(w, http.StatusOK, map[string]any{"input_tokens": estimateTokens(chars)})
}

func anthropicUsage(obj map[string]any) (in, out int) {
	usage, _ := obj["usage"].(map[string]any)
	return intOf(usage["input_tokens"]), intOf(usage["output_tokens"])
}

func intOf(v any) int {
	if f, ok := v.(float64); ok {
		return int(f)
	}
	return 0
}

func anthropicTextLen(obj map[string]any) int {
	content, _ := obj["content"].([]any)
	total := 0
	for _, c := range content {
		m, ok := c.(map[string]any)
		if !ok {
			continue
		}
		if t, ok := m["text"].(string); ok {
			total += len(t)
		}
		if t, ok := m["thinking"].(string); ok {
			total += len(t)
		}
	}
	return total
}

func estimateTokens(chars int) int {
	if chars <= 0 {
		return 0
	}
	return (chars + 3) / 4
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
