package server

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"time"

	"scnet2api/internal/scnet"
)

// handleChatCompletions 是 /v1/chat/completions 的主入口。
//
// 上游本身就是 OpenAI 兼容接口，因此本网关做的是“带账号池与余额治理的
// 透明代理”：改写模型名、注入 SCNet 鉴权头、归一化思维链字段、记录用量。
func (s *Server) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
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
	if msgs, ok := payload["messages"].([]any); !ok || len(msgs) == 0 {
		writeErr(w, http.StatusBadRequest, "messages 不能为空", "invalid_request_error")
		return
	}

	model := s.resolveModel(requestModelName(payload))
	payload["model"] = model.ID
	stream := streamFlag(payload)
	// 显式下发 stream=false：上游在缺省时可能按 SSE 返回，与 OpenAI 规范不一致。
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
		Proto: scnet.ProtoChat, Path: "/chat/completions", Body: body,
		Group: s.requestGroup(r), PreferPaid: !model.IsFree(),
	})
	rl := s.newReqLog(key, acctLabel(acct), model.ID, "chat", stream, start, promptLen)
	if err != nil {
		rl.done(0, 0, 0, 0, err)
		writeUpstreamErr(w, err)
		return
	}
	defer resp.Body.Close()

	if stream {
		s.streamChat(w, resp.Body, rl)
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
		log.Printf("上游响应解析失败：account=%s status=%d ct=%q len=%d head=%q",
			acctLabel(acct), resp.StatusCode, resp.Header.Get("Content-Type"), len(rawResp), headOf(rawResp, 160))
		rl.done(0, 0, 0, 0, err)
		writeErr(w, http.StatusBadGateway, "上游响应不是合法 JSON", "upstream_error")
		return
	}
	transformChatResponse(out, model.ID)
	in, outTokens := scnet.ParseUsage(json.RawMessage(mustJSON(map[string]any{"usage": out["usage"]})))
	outLen := chatTextLen(out)

	encoded, err := json.Marshal(out)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "响应序列化失败", "server_error")
		return
	}
	rl.done(http.StatusOK, outLen, in, outTokens, nil)
	writeRawJSON(w, http.StatusOK, encoded)
}

// mustJSON 把任意值序列化（失败返回 nil）。
func mustJSON(v any) []byte {
	if v == nil {
		return nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return raw
}

// transformChatResponse 归一化非流式响应：补 reasoning_content、改回对外模型名。
func transformChatResponse(m map[string]any, publicModel string) {
	if publicModel != "" {
		m["model"] = publicModel
	}
	choices, _ := m["choices"].([]any)
	for _, c := range choices {
		cm, ok := c.(map[string]any)
		if !ok {
			continue
		}
		if msg, ok := cm["message"].(map[string]any); ok {
			addReasoningContent(msg)
		}
	}
}

// transformChatChunk 归一化单个流式 chunk。
func transformChatChunk(m map[string]any, publicModel string) {
	if publicModel != "" {
		m["model"] = publicModel
	}
	choices, _ := m["choices"].([]any)
	for _, c := range choices {
		cm, ok := c.(map[string]any)
		if !ok {
			continue
		}
		if d, ok := cm["delta"].(map[string]any); ok {
			addReasoningContent(d)
		}
	}
}

// addReasoningContent 在 reasoning 非空且 reasoning_content 缺失时补字段。
func addReasoningContent(obj map[string]any) {
	if _, exists := obj["reasoning_content"]; exists {
		return
	}
	if v, ok := obj["reasoning"].(string); ok && v != "" {
		obj["reasoning_content"] = v
	}
}

// streamChat 以 OpenAI SSE 格式流式转发。
func (s *Server) streamChat(w http.ResponseWriter, body io.Reader, rl *reqLog) {
	sw := newSSEWriter(w)
	sw.start()

	var outLen, tokensIn, tokensOut int

	streamErr := scnet.ForEachSSEFrame(body, func(f scnet.SSEFrame) bool {
		if f.Comment != "" {
			sw.comment(f.Comment)
			return true
		}
		if f.Data == "" {
			return true
		}
		if f.Data == scnet.SSEDone {
			sw.done()
			return false
		}
		if f.Object == nil {
			sw.raw("data: " + f.Data + "\n\n")
			return true
		}
		transformChatChunk(f.Object, rl.model)
		if u := f.Object["usage"]; u != nil {
			in, out := scnet.ParseUsage(json.RawMessage(mustJSON(map[string]any{"usage": u})))
			if in > 0 {
				tokensIn = in
			}
			if out > 0 {
				tokensOut = out
			}
		}
		outLen += chatTextLen(f.Object)
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

// acctLabel 返回用于日志的账号标识（不含密钥）。
func acctLabel(a *scnet.Account) string {
	if a == nil {
		return "-"
	}
	return firstNonEmpty(a.Name, a.UserName, a.ID)
}
