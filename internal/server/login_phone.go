package server

import (
	"net/http"
	"strings"
	"time"

	"scnet2api/internal/scnet"
)

// phoneChallengeTTL 是手机号验证码挑战的有效期（与上游短信有效期一致量级）。
const phoneChallengeTTL = 5 * time.Minute

// handleAdminPhoneSend 发送手机号验证码。
//
// 上游会下发会话 Cookie，验证码必须带同一 Cookie 提交；这里把 Cookie
// 只保存在内存，并返回一个一次性 challenge ID 给前端。
func (s *Server) handleAdminPhoneSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "仅支持 POST", "invalid_request_error")
		return
	}
	var req struct {
		Phone string `json:"phone"`
		Proxy string `json:"proxy"`
	}
	raw, _ := readBodyWithLimit(w, r)
	if err := jsonUnmarshal(raw, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体解析失败", "invalid_request_error")
		return
	}
	phone := strings.TrimSpace(req.Phone)
	if phone == "" {
		writeErr(w, http.StatusBadRequest, "phone 不能为空", "invalid_request_error")
		return
	}
	ctx, cancel := contextWithTimeout(r, 40*time.Second)
	defer cancel()
	challenge, err := s.Up.ForProxy(req.Proxy).SendPhoneCode(ctx, phone)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "发送验证码失败: "+err.Error(), "upstream_error")
		return
	}
	id := scnet.NewID("phone")
	s.phoneMu.Lock()
	s.prunePhoneChallengesLocked(time.Now())
	s.phones[id] = challenge
	s.phoneMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"challenge":  id,
		"phone":      maskPhone(phone),
		"expires_in": int(phoneChallengeTTL.Seconds()),
	})
}

// handleAdminPhoneVerify 用手机号 + 验证码登录并添加账号。
func (s *Server) handleAdminPhoneVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "仅支持 POST", "invalid_request_error")
		return
	}
	var req struct {
		Challenge string `json:"challenge"`
		Code      string `json:"code"`
		Name      string `json:"name"`
		Group     string `json:"group"`
		Proxy     string `json:"proxy"`
	}
	raw, _ := readBodyWithLimit(w, r)
	if err := jsonUnmarshal(raw, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "请求体解析失败", "invalid_request_error")
		return
	}
	if strings.TrimSpace(req.Code) == "" {
		writeErr(w, http.StatusBadRequest, "code 不能为空", "invalid_request_error")
		return
	}

	s.phoneMu.Lock()
	s.prunePhoneChallengesLocked(time.Now())
	challenge := s.phones[req.Challenge]
	delete(s.phones, req.Challenge)
	s.phoneMu.Unlock()
	if challenge == nil || challenge.Expired(time.Now(), phoneChallengeTTL) {
		writeErr(w, http.StatusBadRequest, "验证码会话已过期，请重新发送", "invalid_request_error")
		return
	}

	ctx, cancel := contextWithTimeout(r, 90*time.Second)
	defer cancel()
	sess, err := s.Up.ForProxy(req.Proxy).LoginPhone(ctx, challenge, req.Code)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "手机号登录失败: "+err.Error(), "upstream_error")
		return
	}

	acct := &scnet.Account{
		ID:       scnet.NewID("acct"),
		Name:     firstNonEmpty(req.Name, "phone-"+maskPhone(challenge.Phone)),
		Source:   "phone",
		Group:    req.Group,
		Proxy:    req.Proxy,
		Username: challenge.Phone,
		Session:  sess,
		UserID:   sess.UserID,
		UserName: firstNonEmpty(sess.UserName, challenge.Phone),
		FullName: sess.FullName,
		Enabled:  true,
		Status:   "unknown",
	}
	isNew := s.Store.UpsertAccount(acct)
	_ = s.Store.Save()
	if isNew {
		s.applySession(acct.ID, sess)
	}

	if err := s.PrepareAccount(ctx, acct.ID); err != nil {
		writeErr(w, http.StatusBadGateway, "获取模型凭据失败: "+err.Error(), "upstream_error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "account": toAdminAccount(s.Store.Account(acct.ID)),
	})
}

// prunePhoneChallengesLocked 清理过期挑战（调用方持 phoneMu）。
func (s *Server) prunePhoneChallengesLocked(now time.Time) {
	for id, ch := range s.phones {
		if ch.Expired(now, phoneChallengeTTL) {
			delete(s.phones, id)
		}
	}
}

// maskPhone 对手机号打码：前 3 位 + **** + 后 4 位。
func maskPhone(phone string) string {
	phone = strings.TrimSpace(phone)
	if len(phone) <= 7 {
		return "***"
	}
	return phone[:3] + "****" + phone[len(phone)-4:]
}
