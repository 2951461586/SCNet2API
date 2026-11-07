package server

import (
	_ "embed"
	"net/http"
)

// consoleHTML 是内嵌的控制台单页（单文件、无外部依赖、可离线使用）。
//
//go:embed web/index.html
var consoleHTML []byte

// serveConsole 输出控制台单页。
func serveConsole(w http.ResponseWriter, _ *http.Request) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	_, _ = w.Write(consoleHTML)
}
