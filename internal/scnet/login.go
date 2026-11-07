package scnet

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// rsaPublicKeyBase64 是客户端内置的登录公钥（DER / SubjectPublicKeyInfo）。
//
// 从 resources/app.asar 的 main 模块提取；桌面端在 desktopToken 失效后，
// 用它对账号密码做 RSA PKCS#1 v1.5 加密再提交登录。
const rsaPublicKeyBase64 = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALaXEnbjI6fjy+t9W9AiO/KS0q+b/OZFS+7ykinLbiriUx9P8BcuuHnVbXNiZp5jW70eVGBtX4DhGUPzJa1YT/8CAwEAAQ=="

// ErrPasswordTooLong 表示密码超出 512-bit RSA 的加密上限。
var ErrPasswordTooLong = errors.New("密码过长：客户端公钥为 512-bit RSA，最多加密 53 字节")

// PhoneChallenge 是手机号验证码登录的中间态。
//
// 发送验证码时上游会下发会话 Cookie，验证码必须带着它一起提交，
// 因此调用方需要保存 Cookie（本网关只放在内存里）。
type PhoneChallenge struct {
	Phone     string
	Cookie    string
	CreatedAt time.Time
}

// Expired 报告挑战是否已过期（默认 5 分钟）。
func (c *PhoneChallenge) Expired(now time.Time, ttl time.Duration) bool {
	if c == nil {
		return true
	}
	return now.Sub(c.CreatedAt) > ttl
}

// EncryptPassword 用客户端公钥加密密码（PKCS#1 v1.5 → base64）。
func EncryptPassword(password string) (string, error) {
	der, err := base64.StdEncoding.DecodeString(rsaPublicKeyBase64)
	if err != nil {
		return "", fmt.Errorf("登录公钥解析失败: %w", err)
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return "", fmt.Errorf("登录公钥解析失败: %w", err)
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return "", errors.New("登录公钥类型不是 RSA")
	}
	cipher, err := encryptPKCS1v15(pub, []byte(password))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(cipher), nil
}

// encryptPKCS1v15 手工实现 RSAES-PKCS1-v1_5 加密。
//
// 不直接用 rsa.EncryptPKCS1v15：客户端内置的是 512-bit 公钥，Go 1.24 起
// crypto/rsa 会直接拒绝小于 1024-bit 的密钥（"512-bit keys are insecure"）。
// 这里只需要复刻上游要求的报文格式，不承担实际机密性，因此按 RFC 8017
// 做一次模幂即可，与 Node 的 publicEncrypt(RSA_PKCS1_PADDING) 结果等价。
func encryptPKCS1v15(pub *rsa.PublicKey, msg []byte) ([]byte, error) {
	k := pub.Size()
	if len(msg) > k-11 {
		return nil, ErrPasswordTooLong
	}
	psLen := k - len(msg) - 3
	ps := make([]byte, psLen)
	if _, err := rand.Read(ps); err != nil {
		return nil, fmt.Errorf("密码加密失败: %w", err)
	}
	for i := range ps {
		if ps[i] == 0 {
			ps[i] = 1 // PS 必须全部非零
		}
	}
	em := make([]byte, k)
	em[1] = 2
	copy(em[2:], ps)
	em[2+psLen] = 0
	copy(em[3+psLen:], msg)

	m := new(big.Int).SetBytes(em)
	c := new(big.Int).Exp(m, big.NewInt(int64(pub.E)), pub.N)
	out := make([]byte, k)
	c.FillBytes(out)
	return out, nil
}

// postForm 提交表单并返回响应与原始响应体。
func (c *Client) postForm(ctx context.Context, path string, form url.Values, cookie string) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.WebOrigin+path, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Set("source", c.Source)
	req.Header.Set("version", c.Version)
	req.Header.Set("User-Agent", c.UserAgent)
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("SCNet 登录请求失败: %w", err)
	}
	defer resp.Body.Close()
	body, err := LimitReader(resp.Body, maxJSONBytes)
	if err != nil {
		return resp, nil, err
	}
	return resp, body, nil
}

// loginData 是三种登录接口共用的 data 结构。
type loginData struct {
	ID          any    `json:"id"`
	UserName    string `json:"userName"`
	FullName    string `json:"fullName"`
	Token       string `json:"token"`
	AccessToken string `json:"accessToken"`
	AccessJWT   string `json:"X-Jwt-Access-Token"`
	RefreshJWT  string `json:"X-Jwt-Refresh-Token"`
}

// parseLoginEnvelope 校验信封并把 data 解析为会话。
func parseLoginEnvelope(op string, resp *http.Response, body []byte, desktopToken string) (*Session, error) {
	var env envelope
	if err := DecodeJSON(body, &env); err != nil {
		return nil, fmt.Errorf("%s响应解析失败: %w", op, err)
	}
	if code := anyString(env.Code); code != "" && code != "0" {
		return nil, &HTTPError{Op: op, Status: resp.StatusCode, Body: body}
	}
	var data loginData
	if err := DecodeJSON(env.Data, &data); err != nil {
		return nil, fmt.Errorf("%s响应解析失败: %w", op, err)
	}
	token := firstNonEmpty(data.AccessJWT, data.Token, data.AccessToken)
	if token == "" {
		return nil, &HTTPError{Op: op, Status: resp.StatusCode, Body: body}
	}
	long := firstNonEmpty(data.Token, data.AccessToken)
	if long == token || !isDesktopToken(long) {
		long = ""
	}
	cookie := cookieHeader(resp)
	if cookie == "" {
		return nil, fmt.Errorf("%s响应缺少会话 Cookie", op)
	}
	return &Session{
		DesktopToken: desktopToken,
		Cookie:       cookie,
		AccessJWT:    token,
		RefreshJWT:   data.RefreshJWT,
		LongToken:    long,
		UserID:       anyString(data.ID),
		UserName:     data.UserName,
		FullName:     data.FullName,
		IssuedAt:     time.Now().Unix(),
		RefreshedAt:  time.Now().Unix(),
	}, nil
}

// LoginPassword 用账号密码登录（密码自动 RSA 加密）。
//
// 上游：POST /ac/api/auth/loginDesktopClient.action
// 表单：username / password(=base64(RSA(password))) / encrypted=true /
// type=userNameLogin / captcha="" / captchaKey="" / isSevenDaysValidity=true /
// automatic=true / sensors_anon_id=""。
func (c *Client) LoginPassword(ctx context.Context, username, password string) (*Session, error) {
	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		return nil, errors.New("账号密码不能为空")
	}
	encrypted, err := EncryptPassword(password)
	if err != nil {
		return nil, err
	}
	form := url.Values{
		"username":            {username},
		"password":            {encrypted},
		"encrypted":           {"true"},
		"type":                {"userNameLogin"},
		"captcha":             {""},
		"captchaKey":          {""},
		"isSevenDaysValidity": {"true"},
		"automatic":           {"true"},
		"sensors_anon_id":     {""},
	}
	resp, body, err := c.postForm(ctx, "/ac/api/auth/loginDesktopClient.action", form, "")
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, &HTTPError{Op: "SCNet 密码登录", Status: resp.StatusCode, Body: body}
	}
	return parseLoginEnvelope("SCNet 密码登录", resp, body, "")
}

// SendPhoneCode 发送手机号验证码，并返回后续验证所需的 Cookie。
//
// 上游：POST /ac/api/auth/sendDesktopClientPhoneCode.action（表单字段 phoneNum）。
func (c *Client) SendPhoneCode(ctx context.Context, phone string) (*PhoneChallenge, error) {
	phone = strings.TrimSpace(phone)
	if phone == "" {
		return nil, errors.New("手机号不能为空")
	}
	form := url.Values{"phoneNum": {phone}}
	resp, body, err := c.postForm(ctx, "/ac/api/auth/sendDesktopClientPhoneCode.action", form, "")
	if err != nil {
		return nil, err
	}
	var env envelope
	if err := DecodeJSON(body, &env); err != nil {
		return nil, fmt.Errorf("发送验证码响应解析失败: %w", err)
	}
	if code := anyString(env.Code); code != "" && code != "0" {
		return nil, &HTTPError{Op: "SCNet 发送验证码", Status: resp.StatusCode, Body: body}
	}
	cookie := cookieHeader(resp)
	if cookie == "" {
		// 某些灰度环境只回 jsessionid；没有 Cookie 时验证码无法关联，直接报错。
		return nil, errors.New("发送验证码响应缺少会话 Cookie")
	}
	return &PhoneChallenge{Phone: phone, Cookie: cookie, CreatedAt: time.Now()}, nil
}

// LoginPhone 用手机号 + 短信验证码登录。
//
// 上游：POST /ac/api/auth/loginDesktopClientByPhoneCode.action
// 表单：messageCode / sensors_anon_id / isSevenDaysValidity，
// 并携带发送验证码时下发的 Cookie。
func (c *Client) LoginPhone(ctx context.Context, challenge *PhoneChallenge, code string) (*Session, error) {
	if challenge == nil || challenge.Cookie == "" {
		return nil, errors.New("验证码会话已失效，请重新发送")
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return nil, errors.New("验证码不能为空")
	}
	form := url.Values{
		"messageCode":         {code},
		"sensors_anon_id":     {""},
		"isSevenDaysValidity": {"true"},
	}
	resp, body, err := c.postForm(ctx, "/ac/api/auth/loginDesktopClientByPhoneCode.action", form, challenge.Cookie)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, &HTTPError{Op: "SCNet 手机号登录", Status: resp.StatusCode, Body: body}
	}
	sess, err := parseLoginEnvelope("SCNet 手机号登录", resp, body, "")
	if err != nil {
		return nil, err
	}
	if sess.UserName == "" {
		sess.UserName = challenge.Phone
	}
	return sess, nil
}

// isDesktopToken 判断令牌是否是桌面端那种长效 AC JWT。
//
// 只把能长期复用的令牌升级为 desktopToken；30 分钟的会话 JWT（Sugon
// 网关签发）不能当 desktopToken 用，误存会让账号在 20 分钟后无法续期。
func isDesktopToken(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	var claims struct {
		Creator    string `json:"creator"`
		ExpireTime any    `json:"expireTime"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return false
	}
	return claims.Creator == "ac" || claims.ExpireTime != nil
}

// LoginData 暴露登录响应的解析结果（测试 / 诊断用）。
func LoginData(raw json.RawMessage) (*Session, error) {
	var data loginData
	if err := DecodeJSON(raw, &data); err != nil {
		return nil, err
	}
	token := firstNonEmpty(data.AccessJWT, data.Token, data.AccessToken)
	if token == "" {
		return nil, errors.New("缺少 token")
	}
	return &Session{AccessJWT: token, UserID: anyString(data.ID), UserName: data.UserName, FullName: data.FullName}, nil
}
