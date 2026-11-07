// Package store 负责网关状态持久化（账号 / 密钥 / 设置 / 模型 / 日志 / 统计）。
//
// 选号策略在 internal/pool；本包只在持锁状态下调用它，并把结果作为快照交付。
package store

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"scnet2api/internal/pool"
	"scnet2api/internal/scnet"
)

// APIKey 是网关对外签发的调用密钥。
type APIKey struct {
	Key       string `json:"key"`
	Name      string `json:"name"`
	Group     string `json:"group,omitempty"`
	Enabled   bool   `json:"enabled"`
	CreatedAt int64  `json:"created_at"`
	LastUsed  int64  `json:"last_used"`
	Requests  int64  `json:"requests"`
}

// Settings 是运行期可调参数。
type Settings struct {
	ModelAliases   map[string]string `json:"model_aliases"`
	RequestTimeout int               `json:"request_timeout_sec"`
	MaxRetries     int               `json:"max_retries"`
	LogKeep        int               `json:"log_keep"`
	CORSOrigin     string            `json:"cors_origin"`
	AdminPassword  string            `json:"admin_password"`
	FallbackModel  string            `json:"fallback_model"`
	// ProbeMinutes 是后台余额探测周期（0 = 关闭）。
	ProbeMinutes int `json:"probe_minutes"`
	// SessionMinutes 是会话保活周期（默认 20 分钟，短于 JWT 30 分钟）。
	SessionMinutes int `json:"session_minutes"`
	// SearchKeyName 是联网搜索 MCP Key 的名称。
	SearchKeyName string `json:"search_key_name"`
}

// LogEntry 是一条请求日志（只记元信息，不落对话内容）。
type LogEntry struct {
	Time      int64   `json:"time"`
	Key       string  `json:"key"`
	Account   string  `json:"account"`
	Model     string  `json:"model"`
	Endpoint  string  `json:"endpoint"`
	Stream    bool    `json:"stream"`
	Status    int     `json:"status"`
	LatencyMS int64   `json:"latency_ms"`
	PromptLen int     `json:"prompt_len"`
	OutputLen int     `json:"output_len"`
	TokensIn  int     `json:"tokens_in"`
	TokensOut int     `json:"tokens_out"`
	Cost      float64 `json:"cost"`
	Err       string  `json:"err,omitempty"`
}

// Stats 是累计统计。
type Stats struct {
	TotalRequests  int64   `json:"total_requests"`
	FailedRequests int64   `json:"failed_requests"`
	TotalCharsOut  int64   `json:"total_chars_out"`
	TotalTokensIn  int64   `json:"total_tokens_in"`
	TotalTokensOut int64   `json:"total_tokens_out"`
	TotalCost      float64 `json:"total_cost"`
	StartedAt      int64   `json:"started_at"`
	ResetAt        int64   `json:"reset_at,omitempty"`
}

// State 是全部持久化状态。
type State struct {
	Accounts      []*scnet.Account `json:"accounts"`
	Keys          []*APIKey        `json:"keys"`
	Settings      Settings         `json:"settings"`
	Models        []scnet.Model    `json:"models"`
	DefaultModel  string           `json:"default_model"`
	ModelsUpdated int64            `json:"models_updated"`
	Stats         Stats            `json:"-"`
	Logs          []LogEntry       `json:"-"`
}

// legacyState 用于读取旧格式（含 stats / logs）。
type legacyState struct {
	Accounts      []*scnet.Account `json:"accounts"`
	Keys          []*APIKey        `json:"keys"`
	Settings      Settings         `json:"settings"`
	Models        []scnet.Model    `json:"models"`
	DefaultModel  string           `json:"default_model"`
	ModelsUpdated int64            `json:"models_updated"`
	Stats         Stats            `json:"stats"`
	Logs          []LogEntry       `json:"logs"`
}

// Store 是带锁的状态容器。
type Store struct {
	mu    sync.RWMutex
	path  string
	st    *State
	sched *pool.Scheduler

	statsPath string
	logsPath  string
	logs      *logStore

	masterKey  []byte
	encrypted  bool
	lastSaved  []byte
	statsDirty bool

	savesTotal atomic.Int64
	savedBytes atomic.Int64

	saveMu sync.Mutex
}

// DefaultSettings 返回默认设置。
func DefaultSettings() Settings {
	return Settings{
		ModelAliases:   map[string]string{},
		RequestTimeout: 600,
		MaxRetries:     3,
		LogKeep:        500,
		CORSOrigin:     "",
		FallbackModel:  "",
		ProbeMinutes:   15,
		SessionMinutes: 20,
		SearchKeyName:  "SCNet_Client",
	}
}

// DefaultDataPath 返回默认状态文件路径（用户配置目录下）。
func DefaultDataPath() string {
	return defaultDataPath()
}

// Accounts 返回账号快照（深拷贝）。
func (s *Store) Accounts() []*scnet.Account {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*scnet.Account, 0, len(s.st.Accounts))
	for _, a := range s.st.Accounts {
		out = append(out, a.Clone())
	}
	return out
}

// Account 返回指定账号的副本。
func (s *Store) Account(id string) *scnet.Account {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, a := range s.st.Accounts {
		if a.ID == id {
			return a.Clone()
		}
	}
	return nil
}

// AccountByUser 按平台用户 ID 查找账号。
func (s *Store) AccountByUser(userID string) *scnet.Account {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, a := range s.st.Accounts {
		if a.UserID == userID {
			return a.Clone()
		}
	}
	return nil
}

// UpsertAccount 新增或合并账号，返回是否为新账号。
func (s *Store) UpsertAccount(a *scnet.Account) bool {
	if a == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, ex := range s.st.Accounts {
		if ex.ID == a.ID || (a.UserID != "" && ex.UserID == a.UserID) ||
			(a.APIKey != nil && a.APIKey.APIKey != "" && ex.KeyID() == a.KeyID()) {
			a.MergeFrom(ex)
			s.st.Accounts[i] = a
			return false
		}
	}
	if a.ID == "" {
		a.ID = scnet.NewID("acct")
	}
	s.st.Accounts = append(s.st.Accounts, a)
	return true
}

// UpdateAccount 在锁内修改账号。
func (s *Store) UpdateAccount(id string, fn func(*scnet.Account)) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.st.Accounts {
		if a.ID == id {
			fn(a)
			return true
		}
	}
	return false
}

// RemoveAccount 删除账号。
func (s *Store) RemoveAccount(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, a := range s.st.Accounts {
		if a.ID == id {
			s.st.Accounts = append(s.st.Accounts[:i], s.st.Accounts[i+1:]...)
			return true
		}
	}
	return false
}

// NextAccountGroup 按分组选一个账号（快照），无可用账号返回 nil。
//
// preferPaid 为 true 时跳过已知欠费 / 零余额账号（付费模型场景）。
func (s *Store) NextAccountGroup(group string, preferPaid bool) *scnet.Account {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.sched.Pick(s.st.Accounts, group, preferPaid)
	if a == nil {
		return nil
	}
	a.LastUsed = time.Now().Unix()
	return a.Clone()
}

// MarkAccountResult 记录一次上游调用的成败（只改运行态）。
func (s *Store) MarkAccountResult(id string, ok bool, errMsg string) {
	if id == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.st.Accounts {
		if a.ID != id {
			continue
		}
		if ok {
			a.Status = "ok"
			a.Failures = 0
			a.LastErr = ""
		} else {
			a.Status = "error"
			a.LastErr = trimErr(errMsg)
			a.Failures++
			if a.Failures > 5 {
				a.Failures = 5
			}
		}
		return
	}
}

// AccountCount 返回账号总数。
func (s *Store) AccountCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.st.Accounts)
}

// Groups 返回全部分组名。
func (s *Store) Groups() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	seen := map[string]struct{}{}
	var out []string
	for _, a := range s.st.Accounts {
		g := a.GroupName()
		if _, ok := seen[g]; ok {
			continue
		}
		seen[g] = struct{}{}
		out = append(out, g)
	}
	return out
}

func trimErr(msg string) string {
	msg = strings.TrimSpace(msg)
	if len(msg) > 300 {
		return msg[:300] + "…"
	}
	return msg
}

// HasKeys 报告是否已签发任何密钥。
func (s *Store) HasKeys() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, k := range s.st.Keys {
		if k.Enabled {
			return true
		}
	}
	return false
}

// Keys 返回密钥快照。
func (s *Store) Keys() []*APIKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*APIKey, 0, len(s.st.Keys))
	for _, k := range s.st.Keys {
		cp := *k
		out = append(out, &cp)
	}
	return out
}

// ValidKey 校验密钥是否有效。
func (s *Store) ValidKey(key string) bool {
	key = strings.TrimSpace(key)
	if key == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, k := range s.st.Keys {
		if k.Key == key && k.Enabled {
			return true
		}
	}
	return false
}

// KeyGroup 返回密钥绑定的分组（空串表示全部分组）。
func (s *Store) KeyGroup(key string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, k := range s.st.Keys {
		if k.Key == key {
			return strings.TrimSpace(k.Group)
		}
	}
	return ""
}

// AddKey 签发新密钥。
func (s *Store) AddKey(name, group string) *APIKey {
	buf := make([]byte, 24)
	_, _ = rand.Read(buf)
	key := &APIKey{
		Key:       "sk-scnet-" + hex.EncodeToString(buf),
		Name:      strings.TrimSpace(name),
		Group:     strings.TrimSpace(group),
		Enabled:   true,
		CreatedAt: time.Now().Unix(),
	}
	if key.Name == "" {
		key.Name = "key-" + key.Key[len(key.Key)-4:]
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st.Keys = append(s.st.Keys, key)
	return key
}

// ImportKey 导入一个已有密钥（用于迁移 / 环境变量注入）。
func (s *Store) ImportKey(key, name string) bool {
	key = strings.TrimSpace(key)
	if key == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range s.st.Keys {
		if k.Key == key {
			return false
		}
	}
	s.st.Keys = append(s.st.Keys, &APIKey{
		Key: key, Name: name, Enabled: true, CreatedAt: time.Now().Unix(),
	})
	return true
}

// RemoveKey 删除密钥。
func (s *Store) RemoveKey(ref string) bool {
	ref = strings.TrimSpace(ref)
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, k := range s.st.Keys {
		if k.Key == ref || maskKey(k.Key) == ref || k.Name == ref {
			s.st.Keys = append(s.st.Keys[:i], s.st.Keys[i+1:]...)
			return true
		}
	}
	return false
}

// UpdateKey 修改密钥属性。
func (s *Store) UpdateKey(ref string, fn func(*APIKey)) bool {
	ref = strings.TrimSpace(ref)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range s.st.Keys {
		if k.Key == ref || maskKey(k.Key) == ref || k.Name == ref {
			fn(k)
			return true
		}
	}
	return false
}

// TouchKey 记录一次密钥使用。
func (s *Store) TouchKey(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range s.st.Keys {
		if k.Key == key {
			k.LastUsed = time.Now().Unix()
			k.Requests++
			return
		}
	}
}

func maskKey(key string) string { return scnet.Mask(key) }

// MaskKey 是 maskKey 的导出版本（控制台使用）。
func MaskKey(key string) string { return maskKey(key) }

// AppendLog 追加一条请求日志，并在超出保留量时裁剪。
func (s *Store) AppendLog(e LogEntry) {
	s.mu.Lock()
	s.st.Logs = append(s.st.Logs, e)
	keep := s.st.Settings.LogKeep
	if keep <= 0 {
		keep = 500
	}
	var pruned bool
	if len(s.st.Logs) > keep {
		s.st.Logs = append([]LogEntry(nil), s.st.Logs[len(s.st.Logs)-keep:]...)
		pruned = true
	}
	snapshot := append([]LogEntry(nil), s.st.Logs...)
	s.mu.Unlock()

	_ = s.logs.append(e)
	if pruned {
		_ = s.logs.rewrite(snapshot)
	}
}

// Logs 返回最近的日志（按时间正序）。
func (s *Store) Logs(limit int) []LogEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	logs := s.st.Logs
	if limit <= 0 || limit > len(logs) {
		limit = len(logs)
	}
	out := make([]LogEntry, 0, limit)
	for _, e := range logs[len(logs)-limit:] {
		out = append(out, e)
	}
	return out
}

// AddStats 累加一次调用的统计。
func (s *Store) AddStats(e LogEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := &s.st.Stats
	st.TotalRequests++
	if e.Status >= 400 || e.Err != "" {
		st.FailedRequests++
	}
	st.TotalCharsOut += int64(e.OutputLen)
	st.TotalTokensIn += int64(e.TokensIn)
	st.TotalTokensOut += int64(e.TokensOut)
	st.TotalCost += e.Cost
	if st.StartedAt == 0 {
		st.StartedAt = time.Now().Unix()
	}
	s.statsDirty = true
}

// Stats 返回统计快照。
func (s *Store) Stats() Stats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.st.Stats
}

// ResetStats 清零统计（保留启动时间语义，写入 ResetAt）。
func (s *Store) ResetStats() {
	s.mu.Lock()
	defer s.mu.Unlock()
	started := s.st.Stats.StartedAt
	s.st.Stats = Stats{StartedAt: started, ResetAt: time.Now().Unix()}
	s.statsDirty = true
}

// Settings 返回设置副本。
func (s *Store) Settings() Settings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp := s.st.Settings
	if cp.ModelAliases == nil {
		cp.ModelAliases = map[string]string{}
	} else {
		aliases := make(map[string]string, len(cp.ModelAliases))
		for k, v := range cp.ModelAliases {
			aliases[k] = v
		}
		cp.ModelAliases = aliases
	}
	return cp
}

// UpdateSettings 在锁内修改设置。
func (s *Store) UpdateSettings(fn func(*Settings)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.st.Settings)
}

// SetSettings 覆盖设置（保留空白的默认值）。
func (s *Store) SetSettings(in Settings) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if in.ModelAliases == nil {
		in.ModelAliases = map[string]string{}
	}
	if in.RequestTimeout <= 0 {
		in.RequestTimeout = s.st.Settings.RequestTimeout
	}
	if in.MaxRetries <= 0 {
		in.MaxRetries = s.st.Settings.MaxRetries
	}
	if in.LogKeep <= 0 {
		in.LogKeep = s.st.Settings.LogKeep
	}
	if in.SearchKeyName == "" {
		in.SearchKeyName = s.st.Settings.SearchKeyName
	}
	s.st.Settings = in
}

// Models 返回模型目录快照。
func (s *Store) Models() []scnet.Model {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]scnet.Model, len(s.st.Models))
	copy(out, s.st.Models)
	return out
}

// SetModels 覆盖模型目录与默认模型。
func (s *Store) SetModels(models []scnet.Model, defaultID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st.Models = append([]scnet.Model(nil), models...)
	if strings.TrimSpace(defaultID) != "" {
		s.st.DefaultModel = strings.TrimSpace(defaultID)
	}
	s.st.ModelsUpdated = time.Now().Unix()
}

// ModelsUpdated 返回目录更新时间。
func (s *Store) ModelsUpdated() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.st.ModelsUpdated
}

// DefaultModel 返回默认模型 ID。
func (s *Store) DefaultModel() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.st.DefaultModel == "" {
		return scnet.DefaultModel
	}
	return s.st.DefaultModel
}

// SetDefaultModel 设置默认模型。
func (s *Store) SetDefaultModel(id string) {
	id = strings.TrimSpace(id)
	if id == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st.DefaultModel = id
}
