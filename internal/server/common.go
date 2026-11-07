package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"scnet2api/internal/scnet"
	"scnet2api/internal/store"
)

// nonStreamBudget 是非流式请求的整体预算。
const nonStreamBudget = 300 * time.Second

// errNoAccount 是“没有可用账号”的统一错误。
func errNoAccount() error {
	return errors.New("没有可用账号，请先在控制台导入桌面端登录态或添加账号")
}

// lockAccount 返回账号级互斥锁的解锁函数。
func (s *Server) lockAccount(id string) func() {
	s.lockMu.Lock()
	mu, ok := s.accountLocks[id]
	if !ok {
		mu = &sync.Mutex{}
		s.accountLocks[id] = mu
	}
	s.lockMu.Unlock()
	mu.Lock()
	return mu.Unlock
}

// usableAccount 返回第一个启用且已有凭据的账号（控制台 / 后台任务使用）。
func (s *Server) usableAccount(group string) *scnet.Account {
	for _, a := range s.Store.Accounts() {
		if !a.Enabled {
			continue
		}
		if group != "" && !strings.EqualFold(a.GroupName(), group) {
			continue
		}
		if a.APIKey != nil && a.APIKey.APIKey != "" {
			return a
		}
		if a.Session != nil && a.DesktopToken != "" {
			return a
		}
	}
	return nil
}

// ensureSession 保证账号拥有可用会话（必要时用 desktopToken 重新登录）。
// hasPasswordLogin 报告账号是否配置了账号密码登录。
func hasPasswordLogin(a *scnet.Account) bool {
	return a != nil && strings.TrimSpace(a.Username) != "" && a.Password != ""
}

// loginAccount 按可用凭据登录：desktopToken 优先，失败后回落账号密码。
func (s *Server) loginAccount(ctx context.Context, acct *scnet.Account) (*scnet.Session, error) {
	client := s.Up.ForProxy(acct.Proxy)
	var tokenErr error
	if token := strings.TrimSpace(acct.DesktopToken); token != "" {
		sess, err := client.LoginToken(ctx, token)
		if err == nil {
			return sess, nil
		}
		tokenErr = err
	}
	if hasPasswordLogin(acct) {
		sess, err := client.LoginPassword(ctx, acct.Username, acct.Password)
		if err == nil {
			return sess, nil
		}
		if tokenErr != nil {
			return nil, fmt.Errorf("desktopToken 登录失败（%v）；账号密码登录失败（%w）", tokenErr, err)
		}
		return nil, err
	}
	if tokenErr != nil {
		return nil, tokenErr
	}
	return nil, errors.New("账号缺少 desktopToken 或账号密码，无法建立会话")
}

// applySession 把登录结果写回账号（调用方不要持有账号锁以外的锁）。
//
// 登录响应若附带长效令牌，顺手升级为 desktopToken，后续可用更轻的
// token 登录而不是每次都提交账号密码。
func (s *Server) applySession(id string, sess *scnet.Session) {
	s.Store.UpdateAccount(id, func(a *scnet.Account) {
		a.Session = sess
		a.SessionFail = 0
		a.LastErr = ""
		if sess.LongToken != "" {
			a.DesktopToken = sess.LongToken
		}
		a.UserID = firstNonEmpty(sess.UserID, a.UserID)
		a.UserName = firstNonEmpty(sess.UserName, a.UserName)
		a.FullName = firstNonEmpty(sess.FullName, a.FullName)
		if a.Name == "" {
			a.Name = firstNonEmpty(sess.UserName, a.UserName)
		}
	})
	_ = s.Store.Save()
}

// ensureSession 保证账号拥有可用会话（必要时用 desktopToken / 账号密码登录）。
func (s *Server) ensureSession(ctx context.Context, acct *scnet.Account, force bool) (*scnet.Account, error) {
	if acct == nil {
		return nil, errNoAccount()
	}
	unlock := s.lockAccount(acct.ID)
	defer unlock()

	cur := s.Store.Account(acct.ID)
	if cur == nil {
		return nil, errNoAccount()
	}
	if !force && cur.Session.Valid(time.Now()) {
		return cur, nil
	}
	if strings.TrimSpace(cur.DesktopToken) == "" && !hasPasswordLogin(cur) {
		if cur.Session != nil && cur.Session.Cookie != "" && cur.Session.AccessJWT != "" {
			// 手机号验证码等只拿到会话的账号：沿用旧会话，等上游 401 再报告。
			return cur, nil
		}
		return cur, errors.New("账号缺少 desktopToken 或账号密码，无法建立会话")
	}

	loginCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	sess, err := s.loginAccount(loginCtx, cur)
	if err != nil {
		s.Store.UpdateAccount(cur.ID, func(a *scnet.Account) {
			a.SessionFail++
			a.LastErr = err.Error()
			if a.SessionFail >= 2 {
				a.Status = "error"
			}
		})
		_ = s.Store.Save()
		if cur.Session != nil && cur.Session.Cookie != "" && cur.Session.AccessJWT != "" {
			return cur, nil
		}
		return cur, err
	}
	s.applySession(cur.ID, sess)
	return s.Store.Account(cur.ID), nil
}

// ensureCredential 保证账号拥有可用的模型 API Key。
func (s *Server) ensureCredential(ctx context.Context, acct *scnet.Account, force bool) (*scnet.Account, error) {
	if acct == nil {
		return nil, errNoAccount()
	}
	cur := s.Store.Account(acct.ID)
	if cur == nil {
		return nil, errNoAccount()
	}
	if !force && cur.APIKey != nil && cur.APIKey.APIKey != "" {
		return cur, nil
	}
	cur, err := s.ensureSession(ctx, cur, false)
	if err != nil {
		return cur, err
	}

	unlock := s.lockAccount(acct.ID)
	defer unlock()

	cur = s.Store.Account(acct.ID)
	if !force && cur.APIKey != nil && cur.APIKey.APIKey != "" {
		return cur, nil
	}
	client := s.Up.ForProxy(cur.Proxy)
	credCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cred, err := client.EnsureCredential(credCtx, cur.Session)
	if err != nil {
		s.Store.UpdateAccount(cur.ID, func(a *scnet.Account) {
			a.LastErr = err.Error()
			a.Status = "error"
		})
		_ = s.Store.Save()
		return cur, err
	}
	s.Store.UpdateAccount(cur.ID, func(a *scnet.Account) {
		a.APIKey = cred
		a.Status = "ok"
		a.LastErr = ""
	})
	_ = s.Store.Save()
	return s.Store.Account(cur.ID), nil
}

// probeAccount 同步探测账号（调用方已持有账号锁时不要调用，以免死锁）。
func (s *Server) probeAccount(ctx context.Context, id string) {
	acct := s.Store.Account(id)
	if acct == nil || acct.Session == nil {
		return
	}
	unlock := s.lockAccount(id)
	defer unlock()

	cur := s.Store.Account(id)
	if cur == nil || cur.Session == nil {
		return
	}
	cur, err := s.ensureSessionLocked(ctx, cur)
	if err != nil {
		return
	}
	probeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	p, err := s.Up.ForProxy(cur.Proxy).ProbeAccount(probeCtx, cur.Session)
	if err != nil {
		return
	}
	s.Store.UpdateAccount(id, func(a *scnet.Account) {
		a.User = p.User
		a.Balance = p.Balance
		a.ProbedAt = p.CheckedAt
		if p.Cluster != nil {
			a.AccountID = firstNonEmpty(p.Cluster.AccountID, a.AccountID)
			a.GroupID = firstNonEmpty(p.Cluster.GroupID, a.GroupID)
			a.CreateUser = firstNonEmpty(p.Cluster.CreateUser, a.CreateUser)
		}
		if p.User != nil {
			a.UserID = firstNonEmpty(p.User.ID, a.UserID)
			a.UserName = firstNonEmpty(p.User.UserName, a.UserName)
			a.FullName = firstNonEmpty(p.User.FullName, a.FullName)
		}
	})
	_ = s.Store.Save()
}

// ensureSessionLocked 在已持有账号锁的情况下刷新会话。
func (s *Server) ensureSessionLocked(ctx context.Context, cur *scnet.Account) (*scnet.Account, error) {
	if cur.Session.Valid(time.Now()) {
		return cur, nil
	}
	if strings.TrimSpace(cur.DesktopToken) == "" && !hasPasswordLogin(cur) {
		return cur, nil
	}
	sess, err := s.loginAccount(ctx, cur)
	if err != nil {
		return cur, err
	}
	s.applySession(cur.ID, sess)
	return s.Store.Account(cur.ID), nil
}

// probeAsync 异步探测账号（带去重与并发上限）。
func (s *Server) probeAsync(acct *scnet.Account) {
	if acct == nil || acct.ID == "" || acct.Session == nil {
		return
	}
	s.probeMu.Lock()
	if _, busy := s.probing[acct.ID]; busy {
		s.probeMu.Unlock()
		return
	}
	s.probing[acct.ID] = struct{}{}
	s.probeMu.Unlock()

	go func() {
		defer func() {
			s.probeMu.Lock()
			delete(s.probing, acct.ID)
			s.probeMu.Unlock()
		}()
		s.probeSem <- struct{}{}
		defer func() { <-s.probeSem }()
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		s.probeAccount(ctx, acct.ID)
	}()
}

// acquireAccount 占用一个账号并发槽。
func (s *Server) acquireAccount(id string) bool {
	s.inflightMu.Lock()
	defer s.inflightMu.Unlock()
	if s.inflight[id] >= accountConcurrency {
		return false
	}
	s.inflight[id]++
	return true
}

// releaseAccount 释放账号并发槽。
func (s *Server) releaseAccount(id string) {
	s.inflightMu.Lock()
	defer s.inflightMu.Unlock()
	if s.inflight[id] <= 1 {
		delete(s.inflight, id)
		return
	}
	s.inflight[id]--
}

// releaseBody 在响应体关闭时释放账号槽位。
type releaseBody struct {
	io.ReadCloser
	release func()
	once    sync.Once
}

func (b *releaseBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(b.release)
	return err
}

// llmCall 描述一次上游模型调用。
type llmCall struct {
	Proto      scnet.Protocol
	Path       string
	Body       []byte
	Header     http.Header
	Group      string
	PreferPaid bool
}

// openLLM 选择账号、刷新凭据并调用上游，失败时换号重试。
func (s *Server) openLLM(ctx context.Context, call llmCall) (*http.Response, *scnet.Account, error) {
	accounts := s.Store.Accounts()
	if len(accounts) == 0 {
		return nil, nil, errNoAccount()
	}
	settings := s.Store.Settings()
	maxTries := settings.MaxRetries
	if maxTries <= 0 {
		maxTries = 3
	}
	if maxTries > len(accounts)+2 {
		maxTries = len(accounts) + 2
	}

	var (
		lastErr   error
		used      *scnet.Account
		refreshed = map[string]bool{}
	)
	for i := 0; i < maxTries; i++ {
		acct := s.Store.NextAccountGroup(call.Group, call.PreferPaid)
		if acct == nil {
			break
		}
		used = acct
		if !s.acquireAccount(acct.ID) {
			lastErr = errors.New("账号并发已满，请稍后重试")
			continue
		}

		prepared, err := s.ensureCredential(ctx, acct, false)
		if err != nil {
			s.releaseAccount(acct.ID)
			lastErr = err
			s.Store.MarkAccountResult(acct.ID, false, err.Error())
			continue
		}
		if prepared == nil || prepared.APIKey == nil {
			s.releaseAccount(acct.ID)
			lastErr = errNoAccount()
			continue
		}

		resp, err := s.callUpstream(ctx, prepared, call)
		if err != nil {
			s.releaseAccount(acct.ID)
			lastErr = err
			s.Store.MarkAccountResult(acct.ID, false, err.Error())
			if ctx.Err() != nil {
				break
			}
			continue
		}
		if resp.StatusCode/100 == 2 {
			s.Store.MarkAccountResult(acct.ID, true, "")
			resp.Body = &releaseBody{ReadCloser: resp.Body, release: func() { s.releaseAccount(acct.ID) }}
			return resp, prepared, nil
		}

		payload, readErr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		_ = resp.Body.Close()
		s.releaseAccount(acct.ID)
		if readErr != nil {
			lastErr = readErr
			s.Store.MarkAccountResult(acct.ID, false, readErr.Error())
			continue
		}
		httpErr := &scnet.HTTPError{Op: "上游推理", Status: resp.StatusCode, Body: payload}

		// 鉴权失败：强制重建 Key 后重试一次同一个账号。
		if httpErr.AuthFailed() && !refreshed[acct.ID] {
			refreshed[acct.ID] = true
			lastErr = httpErr
			if _, err := s.ensureCredential(ctx, acct, true); err == nil {
				i--
				continue
			}
		}
		// 余额不足：换下一个账号（可能仍有免费账号 / 有余额的账号）。
		if httpErr.BalanceExhausted() {
			lastErr = httpErr
			s.Store.MarkAccountResult(acct.ID, false, "余额不足")
			s.Store.UpdateAccount(acct.ID, func(a *scnet.Account) {
				if a.Balance == nil {
					a.Balance = &scnet.Balance{Currency: "CNY"}
				}
				a.Balance.Unpaid = true
				a.Balance.CheckedAt = time.Now().Unix()
				a.Balance.Note = "上游返回余额不足"
			})
			_ = s.Store.Save()
			continue
		}
		// 请求本身的问题：直接回传，不浪费其他账号。
		if !httpErr.Retryable() {
			return nil, prepared, httpErr
		}
		lastErr = httpErr
		s.Store.MarkAccountResult(acct.ID, false, httpErr.Error())
		if ctx.Err() != nil {
			break
		}
	}
	if lastErr == nil {
		lastErr = errors.New("全部账号均不可用")
	}
	return nil, used, lastErr
}

// callUpstream 按协议发起请求。
func (s *Server) callUpstream(ctx context.Context, acct *scnet.Account, call llmCall) (*http.Response, error) {
	client := s.Up.ForProxy(acct.Proxy)
	switch call.Proto {
	case scnet.ProtoAnthropic:
		return client.Messages(ctx, acct.APIKey, call.Body, call.Header)
	case scnet.ProtoResponses:
		return client.Responses(ctx, acct.APIKey, call.Body, call.Header)
	default:
		return client.Chat(ctx, acct.APIKey, call.Body, call.Header)
	}
}

// writeUpstreamErr 把上游错误原样（或包装后）返回给客户端。
func writeUpstreamErr(w http.ResponseWriter, err error) {
	var he *scnet.HTTPError
	if errors.As(err, &he) {
		if json.Valid(he.Body) && len(he.Body) > 0 {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(he.Status)
			_, _ = w.Write(he.Body)
			return
		}
		writeErr(w, he.Status, he.Error(), "upstream_error")
		return
	}
	if errors.Is(err, context.Canceled) {
		return
	}
	if errors.Is(err, context.DeadlineExceeded) {
		writeErr(w, http.StatusGatewayTimeout, "上游请求超时", "upstream_error")
		return
	}
	writeErr(w, http.StatusBadGateway, err.Error(), "upstream_error")
}

// writeAnthropicErr 按 Anthropic 错误结构返回。
func writeAnthropicErr(w http.ResponseWriter, status int, typ, msg string) {
	writeJSON(w, status, map[string]any{
		"type":  "error",
		"error": map[string]any{"type": typ, "message": msg},
	})
}

// writeAnthropicUpstreamErr 按 Anthropic 错误结构回传上游错误。
func writeAnthropicUpstreamErr(w http.ResponseWriter, err error) {
	var he *scnet.HTTPError
	if errors.As(err, &he) {
		typ := "api_error"
		switch he.Status {
		case http.StatusBadRequest, http.StatusNotFound, http.StatusUnprocessableEntity:
			typ = "invalid_request_error"
		case http.StatusUnauthorized, http.StatusForbidden:
			typ = "authentication_error"
		case http.StatusTooManyRequests:
			typ = "rate_limit_error"
		}
		writeAnthropicErr(w, he.Status, typ, he.Error())
		return
	}
	if errors.Is(err, context.Canceled) {
		return
	}
	writeAnthropicErr(w, http.StatusBadGateway, "api_error", err.Error())
}

// reqLog 汇总一次请求的日志与统计。
type reqLog struct {
	s         *Server
	key       string
	account   string
	model     string
	endpoint  string
	stream    bool
	start     time.Time
	promptLen int
}

func (s *Server) newReqLog(key, account, model, endpoint string, stream bool, start time.Time, promptLen int) *reqLog {
	if key != "" {
		s.Store.TouchKey(key)
	}
	if key != "" {
		key = scnet.Mask(key)
	}
	return &reqLog{s: s, key: key, account: account, model: model, endpoint: endpoint,
		stream: stream, start: start, promptLen: promptLen}
}

func (rl *reqLog) done(status, outLen, tokensIn, tokensOut int, err error) {
	if rl == nil || rl.s == nil {
		return
	}
	e := storeLogEntry(rl, status, outLen, tokensIn, tokensOut, err)
	rl.s.Store.AppendLog(e)
	rl.s.Store.AddStats(e)
	if err != nil {
		log.Printf("请求失败 endpoint=%s model=%s account=%s status=%d err=%v", rl.endpoint, rl.model, rl.account, status, err)
	}
}

// storeLogEntry 把请求上下文组装为持久化日志。
func storeLogEntry(rl *reqLog, status, outLen, tokensIn, tokensOut int, err error) store.LogEntry {
	e := store.LogEntry{
		Time:      time.Now().Unix(),
		Key:       rl.key,
		Account:   rl.account,
		Model:     rl.model,
		Endpoint:  rl.endpoint,
		Stream:    rl.stream,
		Status:    status,
		LatencyMS: time.Since(rl.start).Milliseconds(),
		PromptLen: rl.promptLen,
		OutputLen: outLen,
		TokensIn:  tokensIn,
		TokensOut: tokensOut,
	}
	if err != nil {
		e.Err = trimLogErr(err.Error())
	}
	if e.Status == 0 && err == nil {
		e.Status = http.StatusOK
	}
	return e
}

func trimLogErr(msg string) string {
	msg = strings.TrimSpace(msg)
	if len(msg) > 300 {
		return msg[:300] + "…"
	}
	return msg
}

// PrepareAccount 完成一次完整的账号准备：登录 → 取模型 Key → 探测余额。
//
// 供 main（启动 / -import）与控制台「刷新」复用。
func (s *Server) PrepareAccount(ctx context.Context, id string) error {
	acct := s.Store.Account(id)
	if acct == nil {
		return errNoAccount()
	}
	if _, err := s.ensureSession(ctx, acct, true); err != nil {
		return err
	}
	if _, err := s.ensureCredential(ctx, s.Store.Account(id), true); err != nil {
		return err
	}
	s.probeAccount(ctx, id)
	cur := s.Store.Account(id)
	if cur == nil || cur.APIKey == nil || cur.APIKey.APIKey == "" {
		return errors.New("模型凭据不可用")
	}
	return nil
}

// EnsureSession 是 ensureSession 的导出版本（后台保活使用）。
func (s *Server) EnsureSession(ctx context.Context, id string, force bool) (*scnet.Account, error) {
	acct := s.Store.Account(id)
	if acct == nil {
		return nil, errNoAccount()
	}
	return s.ensureSession(ctx, acct, force)
}

// ProbeAccountAsync 异步探测指定账号（带去重）。
func (s *Server) ProbeAccountAsync(id string) {
	acct := s.Store.Account(id)
	if acct == nil {
		return
	}
	s.probeAsync(acct)
}
