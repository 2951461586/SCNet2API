package scnet

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestForEachSSEFrame(t *testing.T) {
	stream := ": ping\n\n" +
		"event: message_start\n" +
		"data: {\"type\":\"message_start\"}\n\n" +
		"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n" +
		"data: [DONE]\n\n"
	var frames []SSEFrame
	err := ForEachSSEFrame(strings.NewReader(stream), func(f SSEFrame) bool {
		frames = append(frames, f)
		return true
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) != 4 {
		t.Fatalf("frames=%d %+v", len(frames), frames)
	}
	if frames[0].Comment != ": ping" {
		t.Fatalf("comment=%q", frames[0].Comment)
	}
	if frames[1].Event != "message_start" || frames[1].Object == nil {
		t.Fatalf("event frame=%+v", frames[1])
	}
	if frames[2].Object == nil {
		t.Fatal("chunk not parsed")
	}
	if frames[3].Data != SSEDone {
		t.Fatalf("done=%q", frames[3].Data)
	}
}

func TestTokenDelta(t *testing.T) {
	obj := map[string]any{
		"choices": []any{map[string]any{
			"delta": map[string]any{"content": "hello", "reasoning_content": "think"},
		}},
	}
	c, r := TokenDelta(obj)
	if c != "hello" || r != "think" {
		t.Fatalf("content=%q reasoning=%q", c, r)
	}
}

func TestAnthropicDelta(t *testing.T) {
	obj := map[string]any{"delta": map[string]any{"type": "thinking_delta", "thinking": "plan"}}
	c, r := AnthropicDelta(obj)
	if c != "" || r != "plan" {
		t.Fatalf("content=%q reasoning=%q", c, r)
	}
}

func TestParseUsage(t *testing.T) {
	in, out := ParseUsage(json.RawMessage(`{"usage":{"prompt_tokens":32,"completion_tokens":12}}`))
	if in != 32 || out != 12 {
		t.Fatalf("openai usage %d/%d", in, out)
	}
	in, out = ParseUsage(json.RawMessage(`{"usage":{"input_tokens":7,"output_tokens":9}}`))
	if in != 7 || out != 9 {
		t.Fatalf("anthropic usage %d/%d", in, out)
	}
}

func TestParseAnthropicInput(t *testing.T) {
	obj := map[string]any{"message": map[string]any{"usage": map[string]any{"input_tokens": float64(41)}}}
	if got := ParseAnthropicInput(obj); got != 41 {
		t.Fatalf("got %d", got)
	}
}
