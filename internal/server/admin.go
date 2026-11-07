package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"scnet2api/internal/scnet"
	"scnet2api/internal/store"
)

// adminAccount 是控制台展示用的账号视图（凭据全部打码）。
type adminAccount struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Source      string         `json:"source"`
	Group       string         `json:"group"`
	Proxy       string         `json:"proxy,omitempty"`
	Enabled     bool           `json:"enabled"`
	Status      string         `json:"status"`
	LastErr     string         `json:"last_err,omitempty"`
	Failures    int            `json:"failures"`
	LastUsed    int64          `json:"last_used"`
	UserID      string         `json:"user_id,omitempty"`
	UserName    string         `json:"userName,omitempty"`
	FullName    string         `json:"full_name,omitempty"`
	AccountID   string         `json:"account_id,omitempty"`
	GroupID     string         `json:"group_id,omitempty"`
	LoginMode   string         `json:"login_mode"`
	HasToken    bool           `json:"has_token"`
	HasPassword bool           `json:"has_password"`
	HasSession  bool           `json:"has_session"`
	SessionAt   int64          `json:"session_at,omitempty"`
	APIKeyID    string         `json:"api_key_id,omitempty"`
	APIKeyMask  string         `json:"api_key_mask,omitempty"`
	BaseURL     string         `json:"base_url,omitempty"`
	KeySource   string         `json:"key_source,omitempty"`
	SearchKey   bool           `json:"has_search_key"`
	Balance     *scnet.Balance `json:"balance,omitempty"`
	ProbedAt    int64          `json:"probed_at,omitempty"`
}

func toAdminAccount(a *scnet.Account) adminAccount {
	out := adminAccount{
		ID: a.ID, Name: a.Name, Source: a.Source, Group: a.GroupName(), Proxy: a.Proxy,
		Enabled: a.Enabled, Status: a.Status, LastErr: a.LastErr, Failures: a.Failures,
		LastUsed: a.LastUsed, UserID: a.UserID, UserName: a.UserName, FullName: a.FullName,
		AccountID: a.AccountID, GroupID: a.GroupID,
		LoginMode: loginModeOf(a),
		HasToken:  a.DesktopToken != "", HasPassword: hasPasswordLogin(a),
		HasSession: a.Session != nil && a.Session.Cookie != "",
		SearchKey:  a.SearchKey != "", Balance: a.Balance, ProbedAt: a.ProbedAt,
	}
	if a.Session != nil {
		out.SessionAt = a.Session.IssuedAt
	}
	if a.APIKey != nil {
		out.APIKeyID = a.APIKey.KeyID
		out.APIKeyMask = scnet.Mask(a.APIKey.APIKey)
		out.BaseURL = a.APIKey.BaseURL
		out.KeySource = a.APIKey.Source
	}
	return out
}

// handleAdminState 返回控制台所需的完整状态。
func (s *Server) handleAdminState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "仅支持 GET", "invalid_request_error")
		return
	}
	settings := s.Store.Settings()
	accounts := s.Store.Accounts()
	views := make([]adminAccount, 0, len(accounts))
	for _, a := range accounts {
		views = append(views, toAdminAccount(a))
	}
	keys := s.Store.Keys()
	keyViews := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		keyViews = append(keyViews, map[string]any{
			"key": k.Key, "mask": store.MaskKey(k.Key), "name": k.Name, "group": k.Group,
			"enabled": k.Enabled, "created_at": k.CreatedAt, "last_used": k.LastUsed,
			"requests": k.Requests,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"accounts":       views,
		"keys":           keyViews,
		"settings":       redactSettings(settings),
		"models":         s.catalog(),
		"default_model":  s.Store.DefaultModel(),
		"models_updated": s.Store.ModelsUpdated(),
		"stats":          s.Store.Stats(),
		"groups":         s.Store.Groups(),
		"encrypted":      s.Store.Encrypted(),
		"password_creds": countPasswordAccounts(accounts),
		"master_key":     s.Store.MasterKeySet(),
		"version":        s.Version,
		"now":            time.Now().Unix(),
	})
}

// redactSettings 去掉管理密码明文。
func redactSettings(in store.Settings) map[string]any {
	return map[string]any{
		"model_aliases":   in.ModelAliases,
		"request_timeout": in.RequestTimeout,
		"max_retries":     in.MaxRetries,
		"log_keep":        in.LogKeep,
		"cors_origin":     in.CORSOrigin,
		"fallback_model":  in.FallbackModel,
		"probe_minutes":   in.ProbeMinutes,
		"session_minutes": in.SessionMinutes,
		"search_key_name": in.SearchKeyName,
		"has_password":    in.AdminPassword != "",
	}
}

// handleAdminOverview 返回聚合指标。
func (s *Server) handleAdminOverview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "仅支持 GET", "invalid_request_error")
		return
	}
	accounts := s.Store.Accounts()
	ready, errored, owing := 0, 0, 0
	for _, a := range accounts {
		if !a.Enabled {
			continue
		}
		if a.Status == "error" {
			errored++
		} else {
			ready++
		}
		if a.Balance != nil && a.Balance.Unpaid {
			owing++
		}
	}
	settings := s.Store.Settings()
	writeJSON(w, http.StatusOK, map[string]any{
		"accounts":      len(accounts),
		"ready":         ready,
		"errored":       errored,
		"owing":         owing,
		"keys":          len(s.Store.Keys()),
		"models":        len(s.catalog()),
		"default_model": s.Store.DefaultModel(),
		"groups":        s.Store.Groups(),
		"stats":         s.Store.Stats(),
		"settings":      redactSettings(settings),
		"version":       s.Version,
	})
}

// accountAction 是账号管理动作的请求体。
type accountAction struct {
	Action       string `json:"action"`
	ID           string `json:"id"`
	Name         string `json:"name"`
	Group        string `json:"group"`
	Proxy        string `json:"proxy"`
	DesktopToken string `json:"desktop_token"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	UserID       string `json:"user_id"`
	Enabled      *bool  `json:"enabled"`
	Dir          string `json:"dir"`
}

// handleAdminAccounts 处理账号列表与增删改。
func (s *Server) handleAdminAccounts(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		accounts := s.Store.Accounts()
		views := make([]adminAccount, 0, len(accounts))
		for _, a := range accounts {
			views = append(views, toAdminAccount(a))
		}
		writeJSON(w, http.StatusOK, map[string]any{"accounts": views})
		return
	case http.MethodPost:
	case http.MethodDelete:
	default:
		writeErr(w, http.StatusMethodNotAllowed, "不支持的方法", "invalid_request_error")
		return
	}

	var req accountAction
	raw, err := readBodyWithLimit(w, r)
	if err == nil && len(raw) > 0 {
		_ = json.Unmarshal(raw, &req)
	}
	if r.Method == http.MethodDelete {
		req.Action = "delete"
	}
	if req.Action == "" {
		req.Action = r.URL.Query().Get("action")
	}
	if req.ID == "" {
		req.ID = r.URL.Query().Get("id")
	}

	switch strings.ToLower(req.Action) {
	case "add", "token":
		s.adminAddAccount(w, r, req)
	case "import", "import_desktop":
		target := req.Dir
		if target == "" {
			target = s.ClientDir
		}
		added, err := s.ImportDesktop(target)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "导入失败: "+err.Error(), "invalid_request_error")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"added": added, "imported": len(added)})
	case "update":
		if req.ID == "" {
			writeErr(w, http.StatusBadRequest, "缺少 id", "invalid_request_error")
			return
		}
		ok := s.Store.UpdateAccount(req.ID, func(a *scnet.Account) {
			if req.Name != "" {
				a.Name = req.Name
			}
			if req.Group != "" {
				a.Group = req.Group
			}
			if req.Proxy != "" {
				a.Proxy = req.Proxy
			}
			if req.Enabled != nil {
				a.Enabled = *req.Enabled
			}
		})
		if !ok {
			writeErr(w, http.StatusNotFound, "账号不存在", "invalid_request_error")
			return
		}
		_ = s.Store.Save()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	case "delete":
		if !s.Store.RemoveAccount(req.ID) {
			writeErr(w, http.StatusNotFound, "账号不存在", "invalid_request_error")
			return
		}
		_ = s.Store.Save()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	case "enable", "disable":
		if req.ID == "" {
			writeErr(w, http.StatusBadRequest, "缺少 id", "invalid_request_error")
			return
		}
		enabled := strings.EqualFold(req.Action, "enable")
		ok := s.Store.UpdateAccount(req.ID, func(a *scnet.Account) { a.Enabled = enabled })
		if !ok {
			writeErr(w, http.StatusNotFound, "账号不存在", "invalid_request_error")
			return
		}
		_ = s.Store.Save()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	case "refresh", "login":
		if req.ID == "" {
			writeErr(w, http.StatusBadRequest, "缺少 id", "invalid_request_error")
			return
		}
		ctx, cancel := contextWithTimeout(r, 120*time.Second)
		defer cancel()
		acct := s.Store.Account(req.ID)
		if acct == nil {
			writeErr(w, http.StatusNotFound, "账号不存在", "invalid_request_error")
			return
		}
		if _, err := s.ensureSession(ctx, acct, true); err != nil {
			writeErr(w, http.StatusBadGateway, "会话刷新失败: "+err.Error(), "upstream_error")
			return
		}
		if _, err := s.ensureCredential(ctx, acct, true); err != nil {
			writeErr(w, http.StatusBadGateway, "凭据刷新失败: "+err.Error(), "upstream_error")
			return
		}
		s.probeAccount(ctx, req.ID)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "account": toAdminAccount(s.Store.Account(req.ID))})
	case "probe":
		ctx, cancel := contextWithTimeout(r, 120*time.Second)
		defer cancel()
		s.probeAccount(ctx, req.ID)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "account": toAdminAccount(s.Store.Account(req.ID))})
	default:
		writeErr(w, http.StatusBadRequest, "未知 action: "+req.Action, "invalid_request_error")
	}
}

// adminAddAccount 添加账号并立即登录 / 取 Key。
//
// 支持两种凭据：desktopToken（桌面端登录态）或账号密码（可自动续期）。
func (s *Server) adminAddAccount(w http.ResponseWriter, r *http.Request, req accountAction) {
	token := strings.TrimSpace(req.DesktopToken)
	username := strings.TrimSpace(req.Username)
	password := req.Password
	if token == "" && (username == "" || password == "") {
		writeErr(w, http.StatusBadRequest, "需要 desktop_token，或同时提供 username 与 password", "invalid_request_error")
		return
	}
	source := "manual"
	name := firstNonEmpty(req.Name, "token-"+scnet.ShortHash(token))
	switch {
	case token == "":
		source = "password"
		name = firstNonEmpty(req.Name, "user-"+scnet.ShortHash(username))
	case username != "":
		source = "desktop+password"
	}
	acct := &scnet.Account{
		ID:           scnet.NewID("acct"),
		Name:         name,
		Source:       source,
		Group:        req.Group,
		Proxy:        req.Proxy,
		DesktopToken: token,
		Username:     username,
		Password:     password,
		UserID:       req.UserID,
		Enabled:      true,
		Status:       "unknown",
	}
	isNew := s.Store.UpsertAccount(acct)
	_ = s.Store.Save()

	ctx, cancel := contextWithTimeout(r, 150*time.Second)
	defer cancel()
	if err := s.PrepareAccount(ctx, acct.ID); err != nil {
		writeErr(w, http.StatusBadGateway, "登录或取模型凭据失败: "+err.Error(), "upstream_error")
		return
	}
	if isNew {
		go func() {
			refreshCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			if _, err := s.RefreshModels(refreshCtx); err != nil {
				log.Printf("模型目录刷新失败: %v", err)
			}
		}()
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "account": toAdminAccount(s.Store.Account(acct.ID))})
}

// loginModeOf 返回账号可用的登录方式（用于控制台展示）。
func loginModeOf(a *scnet.Account) string {
	var modes []string
	if a.DesktopToken != "" {
		modes = append(modes, "token")
	}
	if hasPasswordLogin(a) {
		modes = append(modes, "password")
	}
	if len(modes) == 0 && a.Session != nil && a.Session.Cookie != "" {
		modes = append(modes, "session")
	}
	if a.Source == "phone" {
		return "phone"
	}
	if len(modes) == 0 {
		return "none"
	}
	return strings.Join(modes, "+")
}

// countPasswordAccounts 统计保存了密码的账号数。
func countPasswordAccounts(accounts []*scnet.Account) int {
	n := 0
	for _, a := range accounts {
		if hasPasswordLogin(a) {
			n++
		}
	}
	return n
}

// handleAdminProbe 批量探测账号余额。
func (s *Server) handleAdminProbe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "仅支持 POST", "invalid_request_error")
		return
	}
	var req struct {
		ID        string `json:"id"`
		Group     string `json:"group"`
		StaleOnly bool   `json:"stale_only"`
		Limit     int    `json:"limit"`
	}
	raw, _ := readBodyWithLimit(w, r)
	_ = json.Unmarshal(raw, &req)
	if req.Limit <= 0 || req.Limit > 50 {
		req.Limit = 50
	}
	accounts := s.Store.Accounts()
	probed, remaining := 0, 0
	ctx, cancel := contextWithTimeout(r, 180*time.Second)
	defer cancel()
	for _, a := range accounts {
		if req.ID != "" && a.ID != req.ID {
			continue
		}
		if req.Group != "" && !strings.EqualFold(a.GroupName(), req.Group) {
			continue
		}
		if req.StaleOnly && a.Balance != nil && a.Balance.CheckedAt > 0 &&
			time.Since(time.Unix(a.Balance.CheckedAt, 0)) < 15*time.Minute {
			continue
		}
		if probed >= req.Limit {
			remaining++
			continue
		}
		s.probeAccount(ctx, a.ID)
		probed++
	}
	writeJSON(w, http.StatusOK, map[string]any{"total": len(accounts), "probed": probed, "remaining": remaining})
}

// handleAdminKeys 处理密钥列表与签发。
func (s *Server) handleAdminKeys(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		keys := s.Store.Keys()
		out := make([]map[string]any, 0, len(keys))
		for _, k := range keys {
			out = append(out, map[string]any{
				"key": k.Key, "mask": store.MaskKey(k.Key), "name": k.Name, "group": k.Group,
				"enabled": k.Enabled, "created_at": k.CreatedAt, "last_used": k.LastUsed,
				"requests": k.Requests,
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{"keys": out})
		return
	case http.MethodPost:
		var req struct {
			Name    string `json:"name"`
			Group   string `json:"group"`
			Action  string `json:"action"`
			Key     string `json:"key"`
			Enabled *bool  `json:"enabled"`
		}
		raw, _ := readBodyWithLimit(w, r)
		_ = json.Unmarshal(raw, &req)
		action := strings.ToLower(req.Action)
		switch action {
		case "", "create":
			k := s.Store.AddKey(req.Name, req.Group)
			_ = s.Store.Save()
			writeJSON(w, http.StatusOK, map[string]any{"key": k.Key, "name": k.Name, "group": k.Group})
		case "enable", "disable":
			enabled := action == "enable"
			if !s.Store.UpdateKey(req.Key, func(k *store.APIKey) { k.Enabled = enabled }) {
				writeErr(w, http.StatusNotFound, "密钥不存在", "invalid_request_error")
				return
			}
			_ = s.Store.Save()
			writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		case "delete":
			if !s.Store.RemoveKey(req.Key) {
				writeErr(w, http.StatusNotFound, "密钥不存在", "invalid_request_error")
				return
			}
			_ = s.Store.Save()
			writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		default:
			writeErr(w, http.StatusBadRequest, "未知 action", "invalid_request_error")
		}
		return
	default:
		writeErr(w, http.StatusMethodNotAllowed, "不支持的方法", "invalid_request_error")
	}
}

// handleAdminLogs 返回最近日志。
func (s *Server) handleAdminLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "仅支持 GET", "invalid_request_error")
		return
	}
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n > 0 && n <= 2000 {
			limit = n
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"logs": s.Store.Logs(limit)})
}

// handleAdminStats 返回 / 重置统计。
func (s *Server) handleAdminStats(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.Store.Stats())
	case http.MethodPost, http.MethodDelete:
		s.Store.ResetStats()
		s.Store.SaveStats()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		writeErr(w, http.StatusMethodNotAllowed, "不支持的方法", "invalid_request_error")
	}
}

// handleAdminSettings 读写设置。
func (s *Server) handleAdminSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, redactSettings(s.Store.Settings()))
	case http.MethodPost:
		var req struct {
			ModelAliases   map[string]string `json:"model_aliases"`
			RequestTimeout int               `json:"request_timeout"`
			MaxRetries     int               `json:"max_retries"`
			LogKeep        int               `json:"log_keep"`
			CORSOrigin     string            `json:"cors_origin"`
			AdminPassword  *string           `json:"admin_password"`
			FallbackModel  string            `json:"fallback_model"`
			ProbeMinutes   *int              `json:"probe_minutes"`
			SessionMinutes *int              `json:"session_minutes"`
			SearchKeyName  string            `json:"search_key_name"`
		}
		raw, _ := readBodyWithLimit(w, r)
		if err := json.Unmarshal(raw, &req); err != nil {
			writeErr(w, http.StatusBadRequest, "请求体解析失败", "invalid_request_error")
			return
		}
		cur := s.Store.Settings()
		if req.ModelAliases != nil {
			cur.ModelAliases = req.ModelAliases
		}
		if req.RequestTimeout > 0 {
			cur.RequestTimeout = req.RequestTimeout
		}
		if req.MaxRetries > 0 {
			cur.MaxRetries = req.MaxRetries
		}
		if req.LogKeep > 0 {
			cur.LogKeep = req.LogKeep
		}
		if req.CORSOrigin != "" || req.AdminPassword == nil {
			// 空串表示“恢复默认仅回环”，因此仅在显式传参时覆盖。
			if _, ok := rawField(raw, "cors_origin"); ok {
				cur.CORSOrigin = req.CORSOrigin
			}
		}
		cur.FallbackModel = req.FallbackModel
		if req.ProbeMinutes != nil {
			cur.ProbeMinutes = *req.ProbeMinutes
		}
		if req.SessionMinutes != nil {
			cur.SessionMinutes = *req.SessionMinutes
		}
		if req.SearchKeyName != "" {
			cur.SearchKeyName = req.SearchKeyName
		}
		if req.AdminPassword != nil {
			cur.AdminPassword = *req.AdminPassword
		}
		s.Store.SetSettings(cur)
		_ = s.Store.Save()
		writeJSON(w, http.StatusOK, redactSettings(s.Store.Settings()))
	default:
		writeErr(w, http.StatusMethodNotAllowed, "不支持的方法", "invalid_request_error")
	}
}

func rawField(raw []byte, name string) (json.RawMessage, bool) {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return nil, false
	}
	v, ok := m[name]
	return v, ok
}

// handleAdminModels 返回模型目录 / 刷新目录 / 设置默认模型。
func (s *Server) handleAdminModels(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{
			"models": s.catalog(), "default_model": s.Store.DefaultModel(),
			"updated": s.Store.ModelsUpdated(),
		})
	case http.MethodPost:
		var req struct {
			Action       string `json:"action"`
			DefaultModel string `json:"default_model"`
		}
		raw, _ := readBodyWithLimit(w, r)
		_ = json.Unmarshal(raw, &req)
		switch strings.ToLower(req.Action) {
		case "refresh":
			ctx, cancel := contextWithTimeout(r, 60*time.Second)
			defer cancel()
			models, err := s.RefreshModels(ctx)
			if err != nil {
				writeErr(w, http.StatusBadGateway, "刷新失败: "+err.Error(), "upstream_error")
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "models": models, "default_model": s.Store.DefaultModel()})
		case "default":
			if req.DefaultModel == "" {
				writeErr(w, http.StatusBadRequest, "缺少 default_model", "invalid_request_error")
				return
			}
			s.Store.SetDefaultModel(req.DefaultModel)
			_ = s.Store.Save()
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "default_model": s.Store.DefaultModel()})
		default:
			writeErr(w, http.StatusBadRequest, "未知 action", "invalid_request_error")
		}
	default:
		writeErr(w, http.StatusMethodNotAllowed, "不支持的方法", "invalid_request_error")
	}
}

// handleAdminImport 从桌面端数据目录导入登录态。
func (s *Server) handleAdminImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "仅支持 POST", "invalid_request_error")
		return
	}
	var req struct {
		Dir string `json:"dir"`
	}
	raw, _ := readBodyWithLimit(w, r)
	_ = json.Unmarshal(raw, &req)
	dir := req.Dir
	if dir == "" {
		dir = s.ClientDir
	}
	added, err := s.ImportDesktop(dir)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "导入失败: "+err.Error(), "invalid_request_error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"added": added, "imported": len(added)})
}

// handleAdminSearch 在控制台里测试联网搜索。
func (s *Server) handleAdminSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "仅支持 POST", "invalid_request_error")
		return
	}
	raw, _ := readBodyWithLimit(w, r)
	var req scnet.SearchRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体解析失败", "invalid_request_error")
		return
	}
	acct := s.usableAccount("")
	if acct == nil {
		writeErr(w, http.StatusServiceUnavailable, errNoAccount().Error(), "upstream_error")
		return
	}
	ctx, cancel := contextWithTimeout(r, 60*time.Second)
	defer cancel()
	acct, err := s.ensureSession(ctx, acct, false)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error(), "upstream_error")
		return
	}
	key, err := s.ensureSearchKey(ctx, acct, false)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error(), "upstream_error")
		return
	}
	res, err := s.Up.ForProxy(acct.Proxy).Search(ctx, key, req)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error(), "upstream_error")
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// --- 导入桌面端登录态 ---

// clientConfig 是 scnet-client 的 config.json 子集。
type clientConfig struct {
	AccessToken string `json:"accessToken"`
	UserInfo    struct {
		ID       any    `json:"id"`
		UserName string `json:"userName"`
		FullName string `json:"fullName"`
		Mobile   string `json:"mobilephoneNum"`
		Email    string `json:"email"`
	} `json:"userInfo"`
}

// ImportDesktop 读取桌面端 config.json 里的 accessToken 并登记为账号。
func (s *Server) ImportDesktop(dir string) ([]string, error) {
	paths := candidateClientDirs(dir)
	if len(paths) == 0 {
		return nil, errors.New("未找到 scnet-client 数据目录，请手动指定路径")
	}
	var lastErr error
	for _, path := range paths {
		cfg, err := readClientConfig(path)
		if err != nil {
			lastErr = err
			continue
		}
		if strings.TrimSpace(cfg.AccessToken) == "" {
			lastErr = errors.New("config.json 中没有 accessToken（请先在桌面端登录）")
			continue
		}
		acct := &scnet.Account{
			ID:           scnet.NewID("acct"),
			Name:         firstNonEmpty("desktop-"+cfg.UserInfo.UserName, "desktop-"+scnet.ShortHash(cfg.AccessToken)),
			Source:       "desktop",
			DesktopToken: cfg.AccessToken,
			UserID:       stringID(cfg.UserInfo.ID),
			UserName:     cfg.UserInfo.UserName,
			FullName:     cfg.UserInfo.FullName,
			Enabled:      true,
			Status:       "unknown",
		}
		isNew := s.Store.UpsertAccount(acct)
		_ = s.Store.Save()
		if isNew {
			return []string{acct.ID}, nil
		}
		return nil, nil
	}
	return nil, lastErr
}

// candidateClientDirs 生成候选的桌面端数据目录。
func candidateClientDirs(dir string) []string {
	var out []string
	add := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		for _, existing := range out {
			if strings.EqualFold(existing, p) {
				return
			}
		}
		out = append(out, p)
	}
	add(dir)
	add(os.Getenv("SCNET2API_CLIENT_DIR"))
	if appData := os.Getenv("APPDATA"); appData != "" {
		add(filepath.Join(appData, "scnet-client"))
	}
	if home, err := os.UserHomeDir(); err == nil {
		add(filepath.Join(home, "AppData", "Roaming", "scnet-client"))
		add(filepath.Join(home, ".config", "scnet-client"))
		add(filepath.Join(home, "Library", "Application Support", "scnet-client"))
	}
	return out
}

// readClientConfig 读取并解析 config.json。
func readClientConfig(dir string) (*clientConfig, error) {
	path := dir
	if info, err := os.Stat(dir); err == nil && info.IsDir() {
		path = filepath.Join(dir, "config.json")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 32<<20))
	if err != nil {
		return nil, err
	}
	var cfg clientConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("%s 解析失败: %w", path, err)
	}
	return &cfg, nil
}

func stringID(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return fmt.Sprintf("%.0f", t)
	}
	return ""
}
