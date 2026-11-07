// Package server 暴露 OpenAI / Anthropic 兼容的 HTTP 接口与控制台。
package server

import (
	"context"
	"log"
	"net/http"
	"sync"
	"time"

	"scnet2api/internal/registry"
	"scnet2api/internal/scnet"
	"scnet2api/internal/store"
)

// Server 是网关 HTTP 服务。
type Server struct {
	Store *store.Store
	Up    *scnet.Client
	// Version 是构建版本（main 注入）。
	Version string
	// ClientDir 是桌面端数据目录（导入登录态用）。
	ClientDir string

	refreshMu sync.Mutex

	// inflight 限制单账号同时进行的上游请求数。
	inflightMu sync.Mutex
	inflight   map[string]int

	// accountLocks 串行化同一账号的会话 / 凭据刷新。
	// 上游登录会轮换 Cookie，并发登录会让另一个请求的会话立即失效。
	lockMu       sync.Mutex
	accountLocks map[string]*sync.Mutex

	// phones 保存手机号验证码登录的一次性挑战（仅内存）。
	phoneMu sync.Mutex
	phones  map[string]*scnet.PhoneChallenge

	// probing 是账号探测的在途去重表。
	probeMu  sync.Mutex
	probing  map[string]struct{}
	probeSem chan struct{}

	// quotaReprobeDelays 是入池后 0 余额复探退避序列（测试可注入）。
	quotaReprobeDelays []time.Duration
}

// accountConcurrency 是单账号并发上限。
const accountConcurrency = 4

// probeWorkers 是全局在途探测上限。
const probeWorkers = 4

// New 构造服务。
func New(st *store.Store) *Server {
	return &Server{
		Store:              st,
		Up:                 scnet.NewClient(),
		inflight:           map[string]int{},
		accountLocks:       map[string]*sync.Mutex{},
		probing:            map[string]struct{}{},
		phones:             map[string]*scnet.PhoneChallenge{},
		probeSem:           make(chan struct{}, probeWorkers),
		quotaReprobeDelays: []time.Duration{0, 2 * time.Minute, 10 * time.Minute},
	}
}

// Handler 返回完整路由。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("pong"))
	})
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/healthz", s.handleHealth)

	// OpenAI 兼容
	mux.HandleFunc("/v1/models", s.withAuth(s.handleModels))
	mux.HandleFunc("/v1/chat/completions", s.withAuth(s.handleChatCompletions))
	mux.HandleFunc("/v1/responses", s.withAuth(s.handleResponses))

	// Anthropic 兼容
	mux.HandleFunc("/v1/messages", s.withAuth(s.handleAnthropicMessages))
	mux.HandleFunc("/v1/messages/count_tokens", s.withAuth(s.handleAnthropicCountTokens))

	// SCNet 原生能力扩展
	mux.HandleFunc("/v1/scnet/web_search", s.withAuth(s.handleWebSearch))
	mux.HandleFunc("/v1/scnet/balance", s.withAuth(s.handleBalance))
	mux.HandleFunc("/v1/scnet/usage", s.withAuth(s.handleUsage))
	mux.HandleFunc("/v1/web_search", s.withAuth(s.handleWebSearch))
	mux.HandleFunc("/v1/balance", s.withAuth(s.handleBalance))
	mux.HandleFunc("/v1/usage", s.withAuth(s.handleUsage))

	// 控制台 API
	mux.HandleFunc("/admin/api/state", s.withAdminAuth(s.handleAdminState))
	mux.HandleFunc("/admin/api/overview", s.withAdminAuth(s.handleAdminOverview))
	mux.HandleFunc("/admin/api/accounts", s.withAdminAuth(s.handleAdminAccounts))
	mux.HandleFunc("/admin/api/accounts/probe", s.withAdminAuth(s.handleAdminProbe))
	mux.HandleFunc("/admin/api/keys", s.withAdminAuth(s.handleAdminKeys))
	mux.HandleFunc("/admin/api/logs", s.withAdminAuth(s.handleAdminLogs))
	mux.HandleFunc("/admin/api/stats", s.withAdminAuth(s.handleAdminStats))
	mux.HandleFunc("/admin/api/settings", s.withAdminAuth(s.handleAdminSettings))
	mux.HandleFunc("/admin/api/models", s.withAdminAuth(s.handleAdminModels))
	mux.HandleFunc("/admin/api/import", s.withAdminAuth(s.handleAdminImport))
	mux.HandleFunc("/admin/api/search", s.withAdminAuth(s.handleAdminSearch))
	mux.HandleFunc("/admin/api/login/phone/send", s.withAdminAuth(s.handleAdminPhoneSend))
	mux.HandleFunc("/admin/api/login/phone/verify", s.withAdminAuth(s.handleAdminPhoneVerify))

	mux.HandleFunc("/", s.handleRoot)
	return s.withCORS(mux)
}

// RefreshModels 从上游拉取模型目录并落盘。
func (s *Server) RefreshModels(ctx context.Context) ([]scnet.Model, error) {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()

	acct := s.usableAccount("")
	if acct == nil {
		return nil, errNoAccount()
	}
	if _, err := s.ensureSession(ctx, acct, false); err != nil {
		return nil, err
	}
	sess := s.Store.Account(acct.ID)
	if sess == nil || sess.Session == nil {
		return nil, errNoAccount()
	}
	models, err := s.Up.FetchModels(ctx, sess.Session)
	if err != nil {
		return nil, err
	}
	defaultID := s.Store.DefaultModel()
	for _, m := range models {
		if m.ID == defaultID {
			defaultID = m.ID
			goto save
		}
	}
	defaultID = scnet.DefaultModel
	for _, m := range models {
		if m.ID == scnet.DefaultModel {
			defaultID = m.ID
		}
	}
save:
	s.Store.SetModels(models, defaultID)
	if err := s.Store.Save(); err != nil {
		log.Printf("保存模型目录失败: %v", err)
	}
	return models, nil
}

// catalog 返回当前模型目录（为空时回落到内置条目）。
func (s *Server) catalog() []scnet.Model {
	models := s.Store.Models()
	if len(models) == 0 {
		return []scnet.Model{scnet.DefaultModelEntry()}
	}
	return models
}

// resolveModel 解析请求里的模型名。
func (s *Server) resolveModel(name string) scnet.Model {
	settings := s.Store.Settings()
	fallback := settings.FallbackModel
	return registry.Resolve(s.catalog(), settings.ModelAliases, name, firstNonEmpty(fallback, s.Store.DefaultModel()))
}

// requestGroup 返回调用方密钥绑定的分组。
func (s *Server) requestGroup(r *http.Request) string {
	return s.Store.KeyGroup(extractKey(r))
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// --- 基础端点 ---

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	accts := s.Store.Accounts()
	ok, fresh, due := 0, 0, 0
	now := time.Now()
	for _, a := range accts {
		if a.Enabled && a.Status != "error" {
			ok++
		}
		if a.Balance != nil && a.Balance.CheckedAt > 0 &&
			now.Sub(time.Unix(a.Balance.CheckedAt, 0)) < 15*time.Minute {
			fresh++
		}
		if a.Balance == nil || a.Balance.CheckedAt == 0 ||
			now.Sub(time.Unix(a.Balance.CheckedAt, 0)) > 15*time.Minute {
			due++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":        "ok",
		"accounts":      len(accts),
		"ready":         ok,
		"quota_fresh":   fresh,
		"quota_due":     due,
		"models":        len(s.catalog()),
		"default_model": s.Store.DefaultModel(),
		"version":       s.Version,
	})
}

func (s *Server) handleModels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "仅支持 GET", "invalid_request_error")
		return
	}
	settings := s.Store.Settings()
	models := registry.List(s.catalog(), settings.ModelAliases)
	now := time.Now().Unix()
	data := make([]map[string]any, 0, len(models))
	for _, m := range models {
		data = append(data, map[string]any{
			"id":       m.ID,
			"object":   "model",
			"created":  now,
			"owned_by": "scnet",
			"scnet": map[string]any{
				"name":           m.Name,
				"brand":          m.Brand,
				"reasoning":      m.Reasoning,
				"input":          m.Input,
				"context_window": m.ContextWindow,
				"max_tokens":     m.MaxTokens,
				"protocols":      m.Protocols,
				"price_label":    m.PriceLabel,
				"free":           m.IsFree(),
			},
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"object": "list", "data": data})
}

// handleRoot 返回控制台单页；其余未知路径返回 404。
func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		writeErr(w, http.StatusNotFound, "未找到该路径", "invalid_request_error")
		return
	}
	serveConsole(w, r)
}
