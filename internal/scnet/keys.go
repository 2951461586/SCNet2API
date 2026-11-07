package scnet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// ProviderError 是带平台错误码的凭据链路错误。
type ProviderError struct {
	Op   string
	Code string
	Msg  string
}

func (e *ProviderError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("%s: %s (code=%s)", e.Op, e.Msg, e.Code)
	}
	return e.Op + ": " + e.Msg
}

// ProviderCode 返回平台错误码。
func (e *ProviderError) ProviderCode() string { return e.Code }

// providerCodeOf 从任意错误中提取平台错误码。
func providerCodeOf(err error) string {
	var pe *ProviderError
	if errors.As(err, &pe) {
		return pe.Code
	}
	var he *HTTPError
	if errors.As(err, &he) {
		return he.Code()
	}
	return ""
}

// extractKey 从平台返回的 data 中提取密钥字符串。
//
// 上游不同接口返回形态不一致：字符串、{apiKey}、{data:{apiKey}} 都有。
func extractKey(raw json.RawMessage) string {
	raw = json.RawMessage(strings.TrimSpace(string(raw)))
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return strings.TrimSpace(s)
	}
	var obj map[string]any
	if json.Unmarshal(raw, &obj) != nil {
		return ""
	}
	for _, key := range []string{"apiKey", "apikey", "key", "secret", "token"} {
		if v, ok := obj[key].(string); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	if nested, ok := obj["data"]; ok {
		if b, err := json.Marshal(nested); err == nil {
			return extractKey(b)
		}
	}
	return ""
}

// ClusterUser 是 /user/users/cluster-user-detail 返回的账号条目（取需要的字段）。
type ClusterUser struct {
	AccountID   string
	GroupID     string
	UserID      string
	CreateUser  string
	AccountName string
	GroupName   string
	ClusterName string
	MemberType  string
	Status      string
	Balance     string
}

// ClusterUsers 拉取当前登录用户的集群账号信息。
func (c *Client) ClusterUsers(ctx context.Context, sess *Session) ([]ClusterUser, error) {
	raw, err := c.ACX(ctx, sess, "GET", "/user/users/cluster-user-detail", nil)
	if err != nil {
		return nil, err
	}
	var rows []map[string]any
	if err := DecodeJSON(raw, &rows); err != nil {
		return nil, fmt.Errorf("集群账号信息解析失败: %w", err)
	}
	out := make([]ClusterUser, 0, len(rows))
	for _, row := range rows {
		detail, _ := row["accountDetail"].(map[string]any)
		cu := ClusterUser{
			AccountID:   str(row["accountId"]),
			GroupID:     str(row["groupId"]),
			UserID:      str(row["userId"]),
			CreateUser:  str(row["userId"]),
			AccountName: str(row["accountName"]),
			GroupName:   str(row["groupName"]),
			ClusterName: str(row["clusterName"]),
			MemberType:  str(row["memberType"]),
			Status:      str(detail["status"]),
			Balance:     str(detail["balance"]),
		}
		if cu.AccountID == "" && detail != nil {
			cu.AccountID = str(detail["id"])
		}
		out = append(out, cu)
	}
	return out, nil
}

func str(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case float64:
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t))
		}
		return fmt.Sprintf("%v", t)
	case nil:
		return ""
	default:
		return strings.TrimSpace(fmt.Sprintf("%v", t))
	}
}

// primaryClusterUser 选出可用的主账号（Leader + 正常状态）。
//
// 上游要求账号为团队 Leader，且账号状态为 normal；否则模型服务 Key
// 无法创建。这里的错误文案与桌面端保持一致，便于对照排障。
func primaryClusterUser(rows []ClusterUser) (ClusterUser, error) {
	if len(rows) == 0 {
		return ClusterUser{}, &ProviderError{Op: "SCNet 账号校验", Code: "API010013", Msg: "账号异常，请联系团队管理员"}
	}
	var leaders []ClusterUser
	seen := map[string]struct{}{}
	for _, r := range rows {
		if _, ok := seen[r.AccountID]; ok {
			continue
		}
		seen[r.AccountID] = struct{}{}
		if strings.EqualFold(r.MemberType, "Leader") {
			leaders = append(leaders, r)
		}
	}
	if len(leaders) != 1 {
		return ClusterUser{}, &ProviderError{Op: "SCNet 账号校验", Code: "API010013",
			Msg: "当前账号管理的团队账号不唯一，请联系团队管理员确认"}
	}
	cu := leaders[0]
	if cu.AccountID == "" || cu.GroupID == "" || cu.CreateUser == "" {
		return ClusterUser{}, &ProviderError{Op: "SCNet 账号校验", Code: "API010013",
			Msg: "团队账号信息不完整，请联系团队管理员"}
	}
	if s := strings.ToLower(cu.Status); s != "" && s != "normal" && s != "active" {
		return ClusterUser{}, &ProviderError{Op: "SCNet 账号校验", Code: "API010013",
			Msg: "团队账号已停用，请联系团队管理员"}
	}
	return cu, nil
}

// EnsureModelService 确认模型服务已授权，未授权时尝试自动开通。
func (c *Client) EnsureModelService(ctx context.Context, sess *Session, accountID string) error {
	if accountID == "" {
		return errors.New("accountId 不能为空")
	}
	q := url.Values{"accountId": {accountID}}
	raw, err := c.ACXQuery(ctx, sess, "GET", "/llm/account/config/status", q, nil)
	if err != nil {
		return err
	}
	var status struct {
		ModelServiceEnabled any `json:"modelServiceEnabled"`
	}
	_ = DecodeJSON(raw, &status)
	switch anyString(status.ModelServiceEnabled) {
	case "1":
		return nil
	case "0", "":
		// 未开通：POST authorize（参数在 query 上，无 body）。
		if _, err := c.ACXQuery(ctx, sess, "POST", "/llm/account/config/authorize", q, nil); err != nil {
			return err
		}
		raw, err = c.ACXQuery(ctx, sess, "GET", "/llm/account/config/status", q, nil)
		if err != nil {
			return err
		}
		_ = DecodeJSON(raw, &status)
		if anyString(status.ModelServiceEnabled) != "1" {
			return &ProviderError{Op: "SCNet 模型服务开通", Code: "API010014", Msg: "模型服务授权未生效"}
		}
		return nil
	default:
		return &ProviderError{Op: "SCNet 模型服务", Code: "API010014", Msg: "模型服务授权状态不可用"}
	}
}

// EnsureCredential 获取（必要时创建）模型服务 API Key。
//
// 链路与桌面端一致：
//  1. 先试 createActivityApiKey（活动 Key，一次直接拿到 apiKey/baseUrl）；
//  2. 失败（API010010）时回落到「标准 Key」：查询已有的
//     scnet-client-member-<userId> → detail → 仍无则 create。
func (c *Client) EnsureCredential(ctx context.Context, sess *Session) (*Credential, error) {
	if raw, err := c.ACX(ctx, sess, "POST", "/llm/api-key/createActivityApiKey", map[string]any{}); err == nil {
		cred := decodeCredential(raw)
		if cred.APIKey != "" {
			cred.Source = "activity"
			return cred, nil
		}
	} else if code := providerCodeOf(err); code != "API010010" {
		return nil, err
	}

	rows, err := c.ClusterUsers(ctx, sess)
	if err != nil {
		return nil, err
	}
	cu, err := primaryClusterUser(rows)
	if err != nil {
		return nil, err
	}
	if err := c.EnsureModelService(ctx, sess, cu.AccountID); err != nil {
		return nil, err
	}
	keyName := "scnet-client-member-" + cu.CreateUser

	records, err := c.listKeys(ctx, sess, cu)
	if err != nil {
		return nil, err
	}
	var existing map[string]any
	for _, rec := range records {
		if str(rec["apiKeyName"]) != keyName {
			continue
		}
		if str(rec["accountId"]) != cu.AccountID {
			continue
		}
		if str(rec["keyStatus"]) != "100" {
			return nil, &ProviderError{Op: "SCNet API Key", Code: "API010010",
				Msg: "客户端 API Key 已失效或受限，请在平台检查该 Key 的状态后重试"}
		}
		existing = rec
		break
	}
	if existing != nil {
		q := url.Values{"id": {str(existing["id"])}}
		raw, err := c.ACXQuery(ctx, sess, "GET", "/llm/api-key/detail", q, nil)
		if err != nil {
			return nil, err
		}
		var detail map[string]any
		_ = DecodeJSON(raw, &detail)
		if str(detail["accountId"]) != cu.AccountID || str(detail["createUser"]) != cu.CreateUser {
			return nil, &ProviderError{Op: "SCNet API Key", Code: "API010010", Msg: "API Key 归属与当前账号不一致"}
		}
		key := extractKey(raw)
		if key == "" || strings.Contains(key, "*") {
			return nil, &ProviderError{Op: "SCNet API Key", Code: "API010010", Msg: "API Key 明文不可用"}
		}
		return &Credential{
			APIKey: key, BaseURL: LLMBase, AnthropicBaseURL: AnthropicBase,
			KeyID: str(detail["id"]), KeyName: keyName, Source: "existing",
		}, nil
	}

	raw, err := c.ACX(ctx, sess, "POST", "/llm/api-key/create", map[string]any{
		"createUser":           cu.CreateUser,
		"apiKeyName":           keyName,
		"serviceTypes":         []string{"model"},
		"accessibleModelScope": "ALL",
		"groupId":              cu.GroupID,
		"accountId":            cu.AccountID,
	})
	if err != nil {
		return nil, err
	}
	key := extractKey(raw)
	if key == "" {
		return nil, &ProviderError{Op: "SCNet API Key", Code: "API010010", Msg: "服务凭据不可用"}
	}
	cred := decodeCredential(raw)
	cred.APIKey = key
	cred.KeyName = keyName
	cred.Source = "created"
	if cred.BaseURL == "" {
		cred.BaseURL = LLMBase
	}
	if cred.AnthropicBaseURL == "" {
		cred.AnthropicBaseURL = AnthropicBase
	}
	return cred, nil
}

// listKeys 分页拉取该账号下的 API Key 列表。
func (c *Client) listKeys(ctx context.Context, sess *Session, cu ClusterUser) ([]map[string]any, error) {
	var out []map[string]any
	for page := 1; ; page++ {
		raw, err := c.ACX(ctx, sess, "POST", "/llm/api-key/query", map[string]any{
			"createUser":  cu.CreateUser,
			"accountId":   cu.AccountID,
			"groupId":     cu.GroupID,
			"serviceType": "model",
			"page":        page,
			"size":        100,
		})
		if err != nil {
			return nil, err
		}
		var payload map[string]any
		if err := DecodeJSON(raw, &payload); err != nil {
			return nil, fmt.Errorf("API Key 列表响应异常: %w", err)
		}
		var rows []map[string]any
		if list, ok := payload["records"].([]any); ok {
			for _, item := range list {
				if rec, ok := item.(map[string]any); ok {
					rows = append(rows, rec)
				}
			}
		} else if list, ok := payload["data"].([]any); ok {
			for _, item := range list {
				if rec, ok := item.(map[string]any); ok {
					rows = append(rows, rec)
				}
			}
		}
		out = append(out, rows...)
		pages := intValue(payload["pages"], 1)
		if page >= pages || page >= 100 {
			break
		}
	}
	return out, nil
}

func intValue(v any, fallback int) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case string:
		var n int
		if _, err := fmt.Sscanf(strings.TrimSpace(t), "%d", &n); err == nil {
			return n
		}
	}
	return fallback
}

// decodeCredential 把 createActivityApiKey 等返回体解析为凭据。
func decodeCredential(raw json.RawMessage) *Credential {
	var payload map[string]any
	_ = DecodeJSON(raw, &payload)
	cred := &Credential{
		APIKey:           extractKey(raw),
		BaseURL:          str(payload["baseUrl"]),
		AnthropicBaseURL: str(payload["anthropicBaseUrl"]),
		DefaultModel:     str(payload["model"]),
		KeyID:            str(payload["id"]),
		KeyName:          str(payload["apiKeyName"]),
	}
	if cred.BaseURL == "" {
		cred.BaseURL = LLMBase
	}
	if cred.AnthropicBaseURL == "" {
		cred.AnthropicBaseURL = AnthropicBase
	}
	return cred
}

// EnsureSearchKey 获取（必要时创建）联网搜索使用的 MCP Key。
//
// 上游 /llm/web-search 只接受 serviceTypes=mcp 的 Key，与模型 Key 不通用。
func (c *Client) EnsureSearchKey(ctx context.Context, sess *Session, accountID string) (string, error) {
	raw, err := c.ACX(ctx, sess, "POST", "/llm/api-key/mcp/create", map[string]any{
		"apiKeyName": "SCNet_Client",
	})
	if err != nil {
		if providerCodeOf(err) != "API010015" {
			return "", err
		}
		// 需要显式 accountId 重试。
		if accountID == "" {
			rows, listErr := c.ClusterUsers(ctx, sess)
			if listErr != nil {
				return "", listErr
			}
			cu, cuErr := primaryClusterUser(rows)
			if cuErr != nil {
				return "", cuErr
			}
			accountID = cu.AccountID
		}
		raw, err = c.ACX(ctx, sess, "POST", "/llm/api-key/mcp/create", map[string]any{
			"apiKeyName": "SCNet_Client",
			"accountId":  accountID,
		})
		if err != nil {
			return "", err
		}
	}
	key := extractKey(raw)
	if key == "" {
		return "", &ProviderError{Op: "SCNet 联网搜索凭据", Code: "API010015", Msg: "MCP Key 不可用"}
	}
	return key, nil
}
