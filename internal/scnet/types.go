// Package scnet 实现 SCNet（超算互联网）客户端服务端接口的逆向复刻。
//
// 桌面端「计算服务」是 Electron + 本地 agent 架构，模型能力来自两个面：
//
//	平台面（会话鉴权，Cookie: Token=… + token: <JWT>）
//	  POST https://www.scnet.cn/ac/api/auth/loginDesktopClientByToken.action
//	  GET  https://www.scnet.cn/acx/user/users/current-user-info
//	  GET  https://www.scnet.cn/acx/user/users/cluster-user-detail
//	  GET  https://www.scnet.cn/acx/llm/account/config/status
//	  POST https://www.scnet.cn/acx/llm/account/config/authorize
//	  GET  https://www.scnet.cn/acx/llm/api/console/model          （模型目录）
//	  POST https://www.scnet.cn/acx/llm/api-key/createActivityApiKey
//	  POST https://www.scnet.cn/acx/llm/api-key/create
//	  GET  https://www.scnet.cn/acx/llm/api-key/detail
//	  POST https://www.scnet.cn/acx/llm/api-key/query
//	  POST https://www.scnet.cn/acx/llm/api-key/mcp/create         （联网搜索 Key）
//
//	模型面（API Key 鉴权，Authorization: Bearer sk-…）
//	  POST https://api.scnet.cn/api/llm/v1/chat/completions
//	  POST https://api.scnet.cn/api/llm/v1/responses
//	  POST https://api.scnet.cn/api/llm/anthropic/v1/messages
//	  GET  https://api.scnet.cn/api/llm/v1/models
//	  POST https://api.scnet.cn/api/llm/web-search
//
// 本包只负责协议与网络，不做号池调度与持久化。
package scnet

import (
	"strings"
	"time"
)

// 协议常量。
const (
	// WebOrigin 是平台网关（会话鉴权、acx 接口）。
	WebOrigin = "https://www.scnet.cn"
	// APIOrigin 是模型网关前缀（API Key 鉴权）。
	APIOrigin = "https://api.scnet.cn/api"
	// LLMBase 是 OpenAI 兼容推理基地址（账号可能下发不同的 baseUrl）。
	LLMBase = APIOrigin + "/llm/v1"
	// AnthropicBase 是 Anthropic Messages 兼容基地址。
	AnthropicBase = APIOrigin + "/llm/anthropic"
	// WebSearchPath 是联网搜索接口（相对 APIOrigin）。
	WebSearchPath = "/llm/web-search"

	// DefaultModel 是目录不可用 / 未指定时的兜底模型。
	DefaultModel = "SCNet-Max"

	// SDKName 是上游可能用于统计的客户端标识（留空即不伪装）。
	// 桌面端请求头包含 source=Electron 与 version，平台面必须保持一致。
	HeaderSource  = "source"
	HeaderVersion = "version"
	HeaderToken   = "token"
	HeaderCookie  = "Cookie"

	// SessionTTL 是会话 JWT 的保守生命周期。
	// 上游 X-Jwt-Access-Token 的有效期为 30 分钟；提前 5 分钟刷新。
	SessionTTL = 20 * time.Minute

	// maxJSONBytes 限制平台面 JSON 响应体大小。
	maxJSONBytes = 16 << 20
)

// Model 是模型目录中的一个条目。
type Model struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Brand         string   `json:"brand,omitempty"`
	Description   string   `json:"description,omitempty"`
	ContextWindow int      `json:"contextWindow,omitempty"`
	MaxTokens     int      `json:"maxTokens,omitempty"`
	Input         []string `json:"input,omitempty"`
	Protocols     []string `json:"protocols,omitempty"`
	Tags          []string `json:"tags,omitempty"`
	PriceLabel    string   `json:"priceLabel,omitempty"`
	Reasoning     bool     `json:"reasoning,omitempty"`
	Free          bool     `json:"free,omitempty"`
	UpdatedAt     int64    `json:"updatedAt,omitempty"`
}

// Supports 报告模型是否支持某个协议（OPENAI_CHAT / OPENAI_RESPONSES / ANTHROPIC）。
func (m Model) Supports(protocol string) bool {
	for _, p := range m.Protocols {
		if strings.EqualFold(p, protocol) {
			return true
		}
	}
	return false
}

// SupportsImage 报告模型是否接受图片输入。
func (m Model) SupportsImage() bool {
	for _, in := range m.Input {
		if strings.EqualFold(in, "image") {
			return true
		}
	}
	return false
}

// ModelCost 返回上游用于展示的价格标签（free / none / special）。
func (m Model) ModelCost() string { return strings.ToLower(strings.TrimSpace(m.PriceLabel)) }

// IsFree 报告模型是否无需余额即可调用。
//
// 上游 priceLabel=free 的模型（目前只有 SCNet-Max）在余额为 0 时仍可用；
// 其余模型会返回 402 Insufficient Balance。
func (m Model) IsFree() bool {
	if m.Free {
		return true
	}
	return m.ModelCost() == "free"
}

// Credential 是平台下发 / 客户端创建的模型服务凭据。
type Credential struct {
	APIKey           string `json:"apiKey"`
	BaseURL          string `json:"baseUrl"`
	AnthropicBaseURL string `json:"anthropicBaseUrl"`
	DefaultModel     string `json:"model,omitempty"`
	KeyID            string `json:"keyId,omitempty"`
	KeyName          string `json:"keyName,omitempty"`
	Source           string `json:"source,omitempty"` // activity / created / existing
}

// Credential.Clone 返回副本。
func (c *Credential) Clone() *Credential {
	if c == nil {
		return nil
	}
	cp := *c
	return &cp
}

// Session 是平台会话（Cookie + JWT），由 desktopToken 换取。
type Session struct {
	DesktopToken string `json:"desktopToken,omitempty"`
	Cookie       string `json:"cookie"`
	AccessJWT    string `json:"accessJwt,omitempty"`
	RefreshJWT   string `json:"refreshJwt,omitempty"`
	// LongToken 是登录响应里可能附带的长效令牌（可当 desktopToken 复用）。
	LongToken   string `json:"longToken,omitempty"`
	UserID      string `json:"userId,omitempty"`
	UserName    string `json:"userName,omitempty"`
	FullName    string `json:"fullName,omitempty"`
	IssuedAt    int64  `json:"issuedAt,omitempty"`
	RefreshedAt int64  `json:"refreshedAt,omitempty"`
}

// Valid 报告会话是否仍在保守有效期内。
func (s *Session) Valid(now time.Time) bool {
	if s == nil || s.Cookie == "" || s.AccessJWT == "" {
		return false
	}
	if s.IssuedAt <= 0 {
		return false
	}
	return now.Sub(time.Unix(s.IssuedAt, 0)) < SessionTTL
}

// Stale 报告会话是否应当提前刷新。
func (s *Session) Stale(now time.Time) bool { return !s.Valid(now) }

// Clone 返回会话副本。
func (s *Session) Clone() *Session {
	if s == nil {
		return nil
	}
	cp := *s
	return &cp
}

// Balance 是平台余额 / 额度视图。
type Balance struct {
	Balance     string `json:"balance,omitempty"`  // 账户可用余额（元）
	Currency    string `json:"currency,omitempty"` // 固定 CNY
	Unpaid      bool   `json:"unpaid"`
	Inactive    bool   `json:"inactive"`
	ModelReady  bool   `json:"model_service_enabled"`
	QuotaRPM    int    `json:"rpm,omitempty"`
	AccountID   string `json:"accountId,omitempty"`
	GroupID     string `json:"groupId,omitempty"`
	GroupName   string `json:"groupName,omitempty"`
	ClusterName string `json:"clusterName,omitempty"`
	MemberType  string `json:"memberType,omitempty"`
	Status      string `json:"status,omitempty"`
	CheckedAt   int64  `json:"checked_at,omitempty"`
	Note        string `json:"note,omitempty"`
}

// Clone 返回余额副本。
func (b *Balance) Clone() *Balance {
	if b == nil {
		return nil
	}
	cp := *b
	return &cp
}

// UserInfo 是平台账号信息（用于展示，不含凭据）。
type UserInfo struct {
	ID       string `json:"id,omitempty"`
	UserName string `json:"userName,omitempty"`
	FullName string `json:"fullName,omitempty"`
	Mobile   string `json:"mobilephoneNum,omitempty"`
	Email    string `json:"email,omitempty"`
	Status   string `json:"status,omitempty"`
	Role     string `json:"roleType,omitempty"`
	Created  string `json:"createTime,omitempty"`
	Login    string `json:"lastLoginTime,omitempty"`
}

// Account 是一个 SCNet 上游账号（= 一个桌面端登录态 + 一个模型 API Key）。
type Account struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Source  string `json:"source"` // desktop / manual / token
	Group   string `json:"group,omitempty"`
	Proxy   string `json:"proxy,omitempty"`
	Enabled bool   `json:"enabled"`
	Status  string `json:"status"` // ok / error / unknown
	Note    string `json:"note,omitempty"`

	// DesktopToken 是桌面端的长效登录令牌；Username / Password 是账号密码
	// 登录方式（密码随状态文件加密保存，用于 token 过期后的自动重登）。
	DesktopToken string   `json:"desktop_token,omitempty"`
	Username     string   `json:"username,omitempty"`
	Password     string   `json:"password,omitempty"`
	Session      *Session `json:"session,omitempty"`

	UserID     string `json:"user_id,omitempty"`
	UserName   string `json:"user_name,omitempty"`
	FullName   string `json:"full_name,omitempty"`
	AccountID  string `json:"account_id,omitempty"`
	GroupID    string `json:"group_id,omitempty"`
	CreateUser string `json:"create_user,omitempty"`

	APIKey      *Credential `json:"credential,omitempty"`
	SearchKey   string      `json:"search_key,omitempty"`
	SearchKeyAt int64       `json:"search_key_at,omitempty"`

	Balance *Balance  `json:"balance,omitempty"`
	User    *UserInfo `json:"user,omitempty"`

	LastUsed int64  `json:"last_used"`
	LastErr  string `json:"last_err"`
	Failures int    `json:"failures"`
	ProbedAt int64  `json:"probed_at,omitempty"`

	// SessionFail 记录会话刷新连续失败次数，用于指数退避。
	SessionFail int `json:"session_fail,omitempty"`
}

// GroupName 返回规范化分组名。
func (a *Account) GroupName() string {
	if a == nil {
		return "default"
	}
	if g := strings.TrimSpace(a.Group); g != "" {
		return g
	}
	return "default"
}

// KeyID 返回 API Key 的稳定短标识（不泄露明文）。
func (a *Account) KeyID() string {
	if a == nil || a.APIKey == nil || a.APIKey.APIKey == "" {
		return ""
	}
	return KeyFingerprint(a.APIKey.APIKey)
}

// Clone 返回账号深拷贝。
func (a *Account) Clone() *Account {
	if a == nil {
		return nil
	}
	cp := *a
	cp.Session = a.Session.Clone()
	cp.APIKey = a.APIKey.Clone()
	cp.Balance = a.Balance.Clone()
	if a.User != nil {
		u := *a.User
		cp.User = &u
	}
	return &cp
}

// MergeFrom 把已有账号 ex 的运行态并入 a。
//
// 重新导入同一个账号时：运行态（失败计数 / 配额 / 会话 / Key）以 ex 为准，
// 身份字段（名称 / 分组 / 代理）只在 a 为空时回落，避免一次导入抹掉
// 已经赚到的会话与凭据。
func (a *Account) MergeFrom(ex *Account) {
	if a == nil || ex == nil {
		return
	}
	a.ID = ex.ID
	a.Failures = ex.Failures
	a.LastUsed = ex.LastUsed
	a.LastErr = ex.LastErr
	a.Status = ex.Status
	a.ProbedAt = ex.ProbedAt
	a.SessionFail = ex.SessionFail
	if a.Session == nil {
		a.Session = ex.Session.Clone()
	}
	if a.APIKey == nil {
		a.APIKey = ex.APIKey.Clone()
	}
	if a.Balance == nil {
		a.Balance = ex.Balance.Clone()
	}
	if a.User == nil && ex.User != nil {
		u := *ex.User
		a.User = &u
	}
	if a.SearchKey == "" {
		a.SearchKey = ex.SearchKey
	}
	if a.SearchKeyAt == 0 {
		a.SearchKeyAt = ex.SearchKeyAt
	}
	fill := []struct {
		dst *string
		src string
	}{
		{&a.Name, ex.Name},
		{&a.Group, ex.Group},
		{&a.Proxy, ex.Proxy},
		{&a.DesktopToken, ex.DesktopToken},
		{&a.Username, ex.Username},
		{&a.Password, ex.Password},
		{&a.UserID, ex.UserID},
		{&a.UserName, ex.UserName},
		{&a.FullName, ex.FullName},
		{&a.AccountID, ex.AccountID},
		{&a.GroupID, ex.GroupID},
		{&a.CreateUser, ex.CreateUser},
	}
	for _, f := range fill {
		if *f.dst == "" {
			*f.dst = f.src
		}
	}
}

// DefaultModelEntry 是目录不可用时的内置兜底条目。
func DefaultModelEntry() Model {
	return Model{
		ID:            DefaultModel,
		Name:          DefaultModel,
		Brand:         "SCNetAI",
		ContextWindow: 1048576,
		MaxTokens:     131072,
		Input:         []string{"text", "image"},
		Protocols:     []string{"OPENAI_CHAT", "OPENAI_RESPONSES", "ANTHROPIC"},
		PriceLabel:    "free",
		Free:          true,
	}
}
