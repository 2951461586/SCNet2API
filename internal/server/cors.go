package server

import (
	"net/http"
	"strings"
)

// withCORS 为数据面添加 CORS 头。
//
// 默认只放行回环来源；配置了 CORSOrigin 时按列表放行（支持 * 通配）。
func (s *Server) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := strings.TrimSpace(r.Header.Get("Origin"))
		allowed := ""
		if origin != "" {
			cfg := strings.TrimSpace(s.Store.Settings().CORSOrigin)
			switch {
			case cfg == "":
				if isLoopbackAddr(r.RemoteAddr) {
					allowed = origin
				}
			case cfg == "*":
				allowed = "*"
			default:
				for _, entry := range strings.Split(cfg, ",") {
					entry = strings.TrimSpace(entry)
					if entry == "" {
						continue
					}
					if strings.EqualFold(entry, origin) || hasWildcard(entry) && wildcardMatch(entry, origin) {
						allowed = origin
						break
					}
				}
			}
		}
		if allowed != "" {
			h := w.Header()
			h.Set("Access-Control-Allow-Origin", allowed)
			h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, x-api-key, anthropic-version, anthropic-beta, x-admin-password")
			h.Set("Access-Control-Max-Age", "600")
			if allowed != "*" {
				h.Add("Vary", "Origin")
			}
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// wildcardMatch 做简单的前缀 / 后缀通配匹配（例如 http://localhost:*）。
func wildcardMatch(pattern, value string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	value = strings.ToLower(strings.TrimSpace(value))
	if pattern == "" {
		return false
	}
	idx := strings.Index(pattern, "*")
	if idx < 0 {
		return pattern == value
	}
	prefix, suffix := pattern[:idx], pattern[idx+1:]
	return strings.HasPrefix(value, prefix) && strings.HasSuffix(value, suffix)
}
