package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"scnet2api/internal/scnet"
)

// handleResponses 透传 OpenAI Responses 协议。
//
// 支持 OPENAI_RESPONSES 的模型（目录里带 protocols）直连上游 /responses；
// 其余模型返回 400，避免用错误的协议语义偷偷降级。
func (s *Server) handleResponses(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "仅支持 POST", "invalid_request_error")
		return
	}
	start := time.Now()

	raw, err := readBodyWithLimit(w, r)
	if err != nil {
		writeErr(w, http.StatusRequestEntityTooLarge, "请求体过大", "invalid_request_error")
		return
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体解析失败: "+err.Error(), "invalid_request_error")
		return
	}
	if payload["input"] == nil && payload["messages"] == nil {
		writeErr(w, http.StatusBadRequest, "input 不能为空", "invalid_request_error")
		return
	}
	model := s.resolveModel(requestModelName(payload))
	if len(model.Protocols) > 0 && !model.Supports("OPENAI_RESPONSES") {
		writeErr(w, http.StatusBadRequest,
			"模型 "+model.ID+" 不支持 OpenAI Responses 协议，请改用 /v1/chat/completions 或换用支持该协议的模型",
			"invalid_request_error")
		return
	}
	payload["model"] = model.ID
	stream := streamFlag(payload)
	payload["stream"] = stream

	body, err := json.Marshal(payload)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "请求序列化失败", "invalid_request_error")
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
	resp, acct, err := s.openLLM(ctx, llmCall{
		Proto: scnet.ProtoResponses, Path: "/responses", Body: body,
		Group: s.requestGroup(r), PreferPaid: !model.IsFree(),
	})
	rl := s.newReqLog(key, acctLabel(acct), model.ID, "responses", stream, start, promptLen)
	if err != nil {
		rl.done(0, 0, 0, 0, err)
		writeUpstreamErr(w, err)
		return
	}
	defer resp.Body.Close()

	if stream {
		s.streamResponses(w, resp.Body, rl)
		return
	}
	rawResp, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		rl.done(0, 0, 0, 0, err)
		writeErr(w, http.StatusBadGateway, "读取上游响应失败: "+err.Error(), "upstream_error")
		return
	}
	var out map[string]any
	if err := json.Unmarshal(rawResp, &out); err != nil {
		rl.done(0, 0, 0, 0, err)
		writeErr(w, http.StatusBadGateway, "上游响应不是合法 JSON", "upstream_error")
		return
	}
	if model.ID != "" {
		out["model"] = model.ID
	}
	in, outTokens := responsesUsage(out)
	outLen := responsesTextLen(out)
	rl.done(http.StatusOK, outLen, in, outTokens, nil)
	writeRawJSON(w, http.StatusOK, rawResp)
}

// streamResponses 原样透传 Responses SSE（事件名 + JSON）。
func (s *Server) streamResponses(w http.ResponseWriter, body io.Reader, rl *reqLog) {
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
		if f.Event != "" {
			name := f.Event
			if name == "response.completed" || name == "response.incomplete" {
				if respObj, ok := f.Object["response"].(map[string]any); ok {
					if u, ok := respObj["usage"].(map[string]any); ok {
						if v, ok := u["input_tokens"].(float64); ok {
							tokensIn = int(v)
						}
						if v, ok := u["output_tokens"].(float64); ok {
							tokensOut = int(v)
						}
					}
				}
			}
			if delta, ok := f.Object["delta"].(string); ok {
				outLen += len(delta)
			}
			raw, _ := json.Marshal(f.Object)
			sw.event(name, raw)
			return true
		}
		if delta, ok := f.Object["delta"].(string); ok {
			outLen += len(delta)
		}
		if raw := jsonEvent(f.Object); raw != nil {
			sw.data(raw)
		}
		return true
	})
	if streamErr != nil {
		if raw := jsonEvent(map[string]any{
			"error": map[string]any{"message": streamErr.Error(), "type": "upstream_error"},
		}); raw != nil {
			sw.data(raw)
		}
	}
	sw.done()
	rl.done(http.StatusOK, outLen, tokensIn, tokensOut, streamErr)
}

func responsesUsage(obj map[string]any) (in, out int) {
	usage, _ := obj["usage"].(map[string]any)
	in = intOf(usage["input_tokens"])
	out = intOf(usage["output_tokens"])
	return in, out
}

func responsesTextLen(obj map[string]any) int {
	total := 0
	if v, ok := obj["output_text"].(string); ok {
		total += len(v)
	}
	output, _ := obj["output"].([]any)
	for _, item := range output {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		content, _ := m["content"].([]any)
		for _, c := range content {
			cm, ok := c.(map[string]any)
			if !ok {
				continue
			}
			if t, ok := cm["text"].(string); ok {
				total += len(t)
			}
		}
		if t, ok := m["summary"].([]any); ok {
			for _, s := range t {
				if sm, ok := s.(map[string]any); ok {
					if txt, ok := sm["text"].(string); ok {
						total += len(txt)
					}
				}
			}
		}
	}
	return total
}
