package scnet

import (
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// EnvOr 读取环境变量，缺失时返回兜底值。
func EnvOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

// KeyFingerprint 返回密钥的稳定短标识：sha256 前 8 字节十六进制。
//
// 日志 / 去重只使用它，绝不落明文。
func KeyFingerprint(key string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(key)))
	return hex.EncodeToString(sum[:8])
}

// ShortHash 返回任意字符串的短哈希（用于展示）。
func ShortHash(s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:4])
}

// Mask 把密钥打码为前 6 位 + … + 后 4 位。
func Mask(key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return ""
	}
	if len(key) <= 12 {
		return "***"
	}
	return key[:6] + "…" + key[len(key)-4:]
}

// NewID 生成账号 ID（时间戳 + 随机后缀，保证可读且唯一）。
func NewID(prefix string) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz"
	buf := make([]byte, 4)
	if _, err := crand.Read(buf); err != nil {
		// 极端情况下退回时间熵，至少保证 ID 形状稳定。
		for i := range buf {
			buf[i] = byte(time.Now().UnixNano() >> (i * 8))
		}
	}
	for i := range buf {
		buf[i] = alphabet[int(buf[i])%len(alphabet)]
	}
	return fmt.Sprintf("%s-%d-%s", prefix, time.Now().UnixNano()/1e6, string(buf))
}

// ParseProxy 把代理 URL 解析成 *url.URL（空串返回 nil）。
func ParseProxy(raw string) *url.URL {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil
	}
	switch u.Scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return nil
	}
	return u
}

// LimitReader 读取最多 n 字节。
func LimitReader(r io.Reader, n int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, n))
}

// DecodeJSON 解析 JSON（忽略空响应体）。
func DecodeJSON(data []byte, v any) error {
	data = []byte(strings.TrimSpace(string(data)))
	if len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, v)
}

// Header 是便捷的多值请求头构造器。
func Header(pairs ...string) http.Header {
	h := http.Header{}
	for i := 0; i+1 < len(pairs); i += 2 {
		if v := pairs[i+1]; v != "" {
			h.Set(pairs[i], v)
		}
	}
	return h
}
