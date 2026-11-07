package scnet

import (
	"bufio"
	"encoding/json"
	"io"
	"strings"
)

// SSEFrame 是解析后的一个 SSE 帧。
//
// 上游会混用 `data:`、`event:`、注释心跳（`: ping`）三种行；
// 这里把 event 名也保留下来，便于 Anthropic 流式原样转发。
type SSEFrame struct {
	Event   string
	Data    string
	Comment string
	Object  map[string]any
}

// SSE 常量。
const (
	SSEDone = "[DONE]"
)

// ForEachSSEFrame 逐帧读取 SSE，回调返回 false 时停止。
//
// 读缓冲固定 1 MiB：模型网关的单个 chunk 可能包含较长的 reasoning；
// bufio.Scanner 默认 64 KiB 会直接报 token too long。
func ForEachSSEFrame(r io.Reader, fn func(SSEFrame) bool) error {
	br := bufio.NewReaderSize(r, 1<<20)
	var (
		event   string
		data    []string
		comment string
		sawData bool
	)
	flush := func() bool {
		if !sawData && comment == "" && event == "" {
			return true
		}
		frame := SSEFrame{Event: event, Data: strings.Join(data, "\n"), Comment: comment}
		if strings.TrimSpace(frame.Data) != "" && strings.TrimSpace(frame.Data) != SSEDone {
			var obj map[string]any
			if json.Unmarshal([]byte(frame.Data), &obj) == nil {
				frame.Object = obj
			}
		}
		event, data, comment, sawData = "", nil, "", false
		return fn(frame)
	}
	for {
		line, err := br.ReadString('\n')
		if len(line) > 0 {
			line = strings.TrimRight(line, "\r\n")
			switch {
			case line == "":
				if !flush() {
					return nil
				}
			case strings.HasPrefix(line, ":"):
				comment = line
			case strings.HasPrefix(line, "data:"):
				sawData = true
				data = append(data, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
			case strings.HasPrefix(line, "event:"):
				event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			}
		}
		if err != nil {
			if err == io.EOF {
				flush()
				return nil
			}
			return err
		}
	}
}

// TokenDelta 从 OpenAI chat chunk 中提取增量文本与思维链。
func TokenDelta(obj map[string]any) (content, reasoning string) {
	choices, _ := obj["choices"].([]any)
	for _, c := range choices {
		cm, ok := c.(map[string]any)
		if !ok {
			continue
		}
		delta, ok := cm["delta"].(map[string]any)
		if !ok {
			continue
		}
		if v, ok := delta["content"].(string); ok {
			content += v
		}
		if v, ok := delta["reasoning_content"].(string); ok {
			reasoning += v
		}
		if v, ok := delta["reasoning"].(string); ok {
			reasoning += v
		}
	}
	return content, reasoning
}

// AnthropicDelta 从 Anthropic 事件中提取文本 / 思维链增量。
func AnthropicDelta(obj map[string]any) (content, reasoning string) {
	delta, _ := obj["delta"].(map[string]any)
	if delta == nil {
		return "", ""
	}
	switch str(delta["type"]) {
	case "text_delta":
		return str(delta["text"]), ""
	case "thinking_delta":
		return "", str(delta["thinking"])
	}
	return "", ""
}

// ParseAnthropicInput 从 Anthropic 事件里读取输入 token 数（message_start）。
func ParseAnthropicInput(obj map[string]any) int {
	if obj == nil {
		return 0
	}
	if msg, ok := obj["message"].(map[string]any); ok {
		if usage, ok := msg["usage"].(map[string]any); ok {
			if v, ok := usage["input_tokens"].(float64); ok {
				return int(v)
			}
		}
	}
	if usage, ok := obj["usage"].(map[string]any); ok {
		if v, ok := usage["input_tokens"].(float64); ok {
			return int(v)
		}
	}
	return 0
}
