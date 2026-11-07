package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"scnet2api/internal/scnet"
)

// searchKeyTTL 是 MCP 搜索 Key 的缓存时间。
const searchKeyTTL = 12 * time.Hour

// handleWebSearch 提供上游联网搜索。
//
// 请求体：{"query":"…","count":10,"freshness":"noLimit","summary":true}
// 上游要求 serviceTypes=mcp 的 Key，与模型 Key 不同，因此这里按账号缓存。
func (s *Server) handleWebSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "仅支持 POST", "invalid_request_error")
		return
	}
	raw, err := readBodyWithLimit(w, r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "请求体过大", "invalid_request_error")
		return
	}
	var req struct {
		Query     string `json:"query"`
		Count     int    `json:"count"`
		Freshness string `json:"freshness"`
		Summary   *bool  `json:"summary"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体解析失败: "+err.Error(), "invalid_request_error")
		return
	}
	if strings.TrimSpace(req.Query) == "" {
		writeErr(w, http.StatusBadRequest, "query 不能为空", "invalid_request_error")
		return
	}
	if req.Count <= 0 {
		req.Count = 10
	}
	summary := true
	if req.Summary != nil {
		summary = *req.Summary
	}

	acct := s.usableAccount(s.requestGroup(r))
	if acct == nil {
		writeErr(w, http.StatusServiceUnavailable, errNoAccount().Error(), "upstream_error")
		return
	}
	acct, err = s.ensureSession(r.Context(), acct, false)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "账号会话不可用: "+err.Error(), "upstream_error")
		return
	}
	searchKey, err := s.ensureSearchKey(r.Context(), acct, false)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "联网搜索凭据不可用: "+err.Error(), "upstream_error")
		return
	}

	ctx, cancel := contextWithTimeout(r, 60*time.Second)
	defer cancel()
	result, err := s.Up.ForProxy(acct.Proxy).Search(ctx, searchKey, scnet.SearchRequest{
		Query: req.Query, Count: req.Count, Freshness: req.Freshness, Summary: summary,
	})
	if err != nil {
		// 401/403 时重建 MCP Key 再试一次（Key 可能被平台轮换）。
		var he *scnet.HTTPError
		if errors.As(err, &he) && he.AuthFailed() {
			searchKey, kerr := s.ensureSearchKey(ctx, acct, true)
			if kerr == nil {
				result, err = s.Up.ForProxy(acct.Proxy).Search(ctx, searchKey, scnet.SearchRequest{
					Query: req.Query, Count: req.Count, Freshness: req.Freshness, Summary: summary,
				})
			}
		}
	}
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error(), "upstream_error")
		return
	}
	writeJSON(w, http.StatusOK, result)
}

// ensureSearchKey 获取并缓存账号的 MCP 搜索 Key。
func (s *Server) ensureSearchKey(ctx context.Context, acct *scnet.Account, force bool) (string, error) {
	if acct == nil {
		return "", errNoAccount()
	}
	if !force && acct.SearchKey != "" && time.Since(time.Unix(acct.SearchKeyAt, 0)) < searchKeyTTL {
		return acct.SearchKey, nil
	}
	unlock := s.lockAccount(acct.ID)
	defer unlock()

	cur := s.Store.Account(acct.ID)
	if cur == nil {
		return "", errNoAccount()
	}
	if !force && cur.SearchKey != "" && time.Since(time.Unix(cur.SearchKeyAt, 0)) < searchKeyTTL {
		return cur.SearchKey, nil
	}
	cur, err := s.ensureSessionLocked(ctx, cur)
	if err != nil {
		return "", err
	}
	key, err := s.Up.ForProxy(cur.Proxy).EnsureSearchKey(ctx, cur.Session, cur.AccountID)
	if err != nil {
		return "", err
	}
	now := time.Now().Unix()
	s.Store.UpdateAccount(cur.ID, func(a *scnet.Account) {
		a.SearchKey = key
		a.SearchKeyAt = now
	})
	_ = s.Store.Save()
	return key, nil
}

// handleBalance 返回当前账号余额 / 额度视图。
func (s *Server) handleBalance(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "仅支持 GET", "invalid_request_error")
		return
	}
	acct := s.usableAccount(s.requestGroup(r))
	if acct == nil {
		writeErr(w, http.StatusServiceUnavailable, errNoAccount().Error(), "upstream_error")
		return
	}
	bal := acct.Balance
	if bal == nil || bal.CheckedAt == 0 || time.Since(time.Unix(bal.CheckedAt, 0)) > 5*time.Minute {
		ctx, cancel := contextWithTimeout(r, 30*time.Second)
		s.probeAccount(ctx, acct.ID)
		cancel()
		if cur := s.Store.Account(acct.ID); cur != nil {
			bal = cur.Balance
		}
	}
	if bal == nil {
		bal = &scnet.Balance{Currency: "CNY", CheckedAt: time.Now().Unix()}
	}
	writeJSON(w, http.StatusOK, bal)
}

// handleUsage 返回账号、会话与凭据的汇总（凭据打码）。
func (s *Server) handleUsage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "仅支持 GET", "invalid_request_error")
		return
	}
	acct := s.usableAccount(s.requestGroup(r))
	if acct == nil {
		writeErr(w, http.StatusServiceUnavailable, errNoAccount().Error(), "upstream_error")
		return
	}
	ctx, cancel := contextWithTimeout(r, 30*time.Second)
	defer cancel()
	if acct.Balance == nil || acct.Balance.CheckedAt == 0 ||
		time.Since(time.Unix(acct.Balance.CheckedAt, 0)) > 5*time.Minute {
		s.probeAccount(ctx, acct.ID)
	}
	cur := s.Store.Account(acct.ID)
	if cur == nil {
		writeErr(w, http.StatusServiceUnavailable, errNoAccount().Error(), "upstream_error")
		return
	}
	probe := &scnet.Probe{User: cur.User, Balance: cur.Balance, CheckedAt: cur.ProbedAt}
	writeJSON(w, http.StatusOK, scnet.Summarize(probe, cur.APIKey, cur.Session))
}

// contextWithTimeout 在请求上下文上追加超时。
func contextWithTimeout(r *http.Request, d time.Duration) (ctx context.Context, cancel context.CancelFunc) {
	return context.WithTimeout(r.Context(), d)
}
