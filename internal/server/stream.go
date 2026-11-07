package server

import (
	"encoding/json"
	"net/http"
)

// sseWriter 封装 SSE 输出。
type sseWriter struct {
	w       http.ResponseWriter
	f       http.Flusher
	started bool
}

func newSSEWriter(w http.ResponseWriter) *sseWriter {
	h := w.Header()
	h.Set("Content-Type", "text/event-stream; charset=utf-8")
	h.Set("Cache-Control", "no-cache, no-transform")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no")
	f, _ := w.(http.Flusher)
	return &sseWriter{w: w, f: f}
}

// start 只写一次响应头。
func (sw *sseWriter) start() {
	if sw.started {
		return
	}
	sw.started = true
	sw.w.WriteHeader(http.StatusOK)
	sw.flush()
}

// flush 刷新到客户端。
func (sw *sseWriter) flush() {
	if sw.f != nil {
		sw.f.Flush()
	}
}

// raw 原样写一段（用于透传上游帧）。
func (sw *sseWriter) raw(text string) {
	sw.start()
	_, _ = sw.w.Write([]byte(text))
	sw.flush()
}

// data 写 data: 帧。
func (sw *sseWriter) data(payload []byte) {
	sw.start()
	_, _ = sw.w.Write([]byte("data: "))
	_, _ = sw.w.Write(payload)
	_, _ = sw.w.Write([]byte("\n\n"))
	sw.flush()
}

// event 写 event+data 帧。
func (sw *sseWriter) event(name string, payload []byte) {
	sw.start()
	if name != "" {
		_, _ = sw.w.Write([]byte("event: " + name + "\n"))
	}
	_, _ = sw.w.Write([]byte("data: "))
	_, _ = sw.w.Write(payload)
	_, _ = sw.w.Write([]byte("\n\n"))
	sw.flush()
}

// comment 写心跳注释。
func (sw *sseWriter) comment(text string) {
	sw.start()
	_, _ = sw.w.Write([]byte(text + "\n\n"))
	sw.flush()
}

// done 写 OpenAI 的结束帧。
func (sw *sseWriter) done() {
	sw.start()
	_, _ = sw.w.Write([]byte("data: [DONE]\n\n"))
	sw.flush()
}

// jsonEvent 把对象序列化为 JSON（失败返回 nil）。
func jsonEvent(v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return raw
}
