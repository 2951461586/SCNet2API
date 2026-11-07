package scnet

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Probe 是账号探测的完整结果。
type Probe struct {
	User       *UserInfo
	Balance    *Balance
	Cluster    *ClusterUser
	ModelReady bool
	CheckedAt  int64
}

// ProbeAccount 拉取账号的会话态信息：用户资料 + 团队账号 + 余额 + 模型服务开关。
//
// 该调用会刷新会话 Cookie 与 JWT（上游 current-user-info 带 refresh=true），
// 因此也可以当作“会话续期”使用。
func (c *Client) ProbeAccount(ctx context.Context, sess *Session) (*Probe, error) {
	if sess == nil || sess.Cookie == "" {
		return nil, fmt.Errorf("会话不可用")
	}
	out := &Probe{CheckedAt: time.Now().Unix()}

	q := url.Values{"includeToken": {"true"}, "refresh": {"true"}}
	if raw, err := c.ACXQuery(ctx, sess, "GET", "/user/users/current-user-info", q, nil); err == nil {
		var u UserInfo
		if DecodeJSON(raw, &u) == nil && (u.UserName != "" || u.ID != "") {
			out.User = &u
		}
	} else if he, ok := err.(*HTTPError); !ok || he.Status != 401 {
		return nil, err
	}

	rows, err := c.ClusterUsers(ctx, sess)
	if err != nil {
		return nil, err
	}
	cu, cuErr := primaryClusterUser(rows)
	if cuErr == nil {
		out.Cluster = &cu
		out.Balance = &Balance{
			Balance:     cu.Balance,
			Currency:    "CNY",
			AccountID:   cu.AccountID,
			GroupID:     cu.GroupID,
			GroupName:   cu.GroupName,
			ClusterName: cu.ClusterName,
			MemberType:  cu.MemberType,
			Status:      cu.Status,
			CheckedAt:   out.CheckedAt,
		}
		if err := c.EnsureModelService(ctx, sess, cu.AccountID); err == nil {
			out.ModelReady = true
		}
		if out.Balance != nil {
			c.fillStatusFlags(ctx, sess, out.Balance)
		}
	} else if len(rows) > 0 {
		// 非 Leader / 多团队：仍然展示第一个账号，但标记不可用原因。
		first := rows[0]
		out.Cluster = &first
		out.Balance = &Balance{
			Balance:     first.Balance,
			Currency:    "CNY",
			AccountID:   first.AccountID,
			GroupID:     first.GroupID,
			GroupName:   first.GroupName,
			ClusterName: first.ClusterName,
			MemberType:  first.MemberType,
			Status:      first.Status,
			CheckedAt:   out.CheckedAt,
			Note:        cuErr.Error(),
		}
	}
	if out.Balance == nil {
		out.Balance = &Balance{Currency: "CNY", CheckedAt: out.CheckedAt}
	}
	if out.User != nil {
		if out.Balance.AccountID == "" {
			out.Balance.AccountID = out.User.ID
		}
	}
	return out, nil
}

// fillStatusFlags 读取模型服务状态里的欠费 / 停用标记。
func (c *Client) fillStatusFlags(ctx context.Context, sess *Session, bal *Balance) {
	accountID := strings.TrimSpace(bal.AccountID)
	if accountID == "" {
		return
	}
	q := url.Values{"accountId": {accountID}}
	raw, err := c.ACXQuery(ctx, sess, "GET", "/llm/account/config/status", q, nil)
	if err != nil {
		return
	}
	var status struct {
		ModelServiceEnabled any `json:"modelServiceEnabled"`
		UnpaidStatus        any `json:"unpaidStatus"`
		InactiveStatus      any `json:"inactiveStatus"`
		OverallRPM          any `json:"overallRpm"`
	}
	if DecodeJSON(raw, &status) != nil {
		return
	}
	bal.ModelReady = anyString(status.ModelServiceEnabled) == "1"
	bal.Unpaid = anyString(status.UnpaidStatus) == "1"
	bal.Inactive = anyString(status.InactiveStatus) == "1"
	bal.QuotaRPM = intValue(status.OverallRPM, 0)
	if bal.Unpaid {
		bal.Note = "账号存在欠费：仅免费模型可用"
	}
}

// VerifyCredential 用模型网关的 /models 验活。
func (c *Client) VerifyCredential(ctx context.Context, cred *Credential) error {
	if cred == nil || cred.APIKey == "" {
		return fmt.Errorf("模型凭据不可用")
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	models, err := c.ListRemoteModels(ctx, cred)
	if err != nil {
		return err
	}
	if len(models) == 0 {
		return fmt.Errorf("模型网关返回空目录")
	}
	return nil
}

// UsageSummary 是 /v1/scnet/usage 的返回结构。
type UsageSummary struct {
	User       *UserInfo   `json:"user,omitempty"`
	Balance    *Balance    `json:"balance,omitempty"`
	Credential *Credential `json:"credential,omitempty"`
	Session    *Session    `json:"session,omitempty"`
}

// Summarize 组装账号用量视图（凭据 / 会话只输出打码信息）。
func Summarize(p *Probe, cred *Credential, sess *Session) *UsageSummary {
	out := &UsageSummary{User: p.User, Balance: p.Balance}
	if cred != nil {
		out.Credential = &Credential{
			APIKey:           Mask(cred.APIKey),
			BaseURL:          cred.BaseURL,
			AnthropicBaseURL: cred.AnthropicBaseURL,
			DefaultModel:     cred.DefaultModel,
			KeyID:            cred.KeyID,
			KeyName:          cred.KeyName,
			Source:           cred.Source,
		}
	}
	if sess != nil {
		// 会话凭据全部打码：desktopToken / Cookie / JWT 都是可直接冒用的凭据。
		out.Session = &Session{
			UserID:      sess.UserID,
			UserName:    sess.UserName,
			FullName:    sess.FullName,
			IssuedAt:    sess.IssuedAt,
			RefreshedAt: sess.RefreshedAt,
			Cookie:      "Token=***",
		}
	}
	return out
}

// DecodeUser 从平台响应中解析用户资料（供上层复用）。
func DecodeUser(raw json.RawMessage) *UserInfo {
	var u UserInfo
	if DecodeJSON(raw, &u) != nil {
		return nil
	}
	return &u
}
