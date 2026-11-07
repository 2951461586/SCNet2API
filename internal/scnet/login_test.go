package scnet

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestEncryptPassword(t *testing.T) {
	enc, err := EncryptPassword("hunter2")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		t.Fatalf("密文不是合法 base64: %v", err)
	}
	// 512-bit RSA → 64 字节密文。
	if len(raw) != 64 {
		t.Fatalf("ciphertext len=%d, want 64", len(raw))
	}
	again, err := EncryptPassword("hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if enc == again {
		t.Fatal("PKCS#1 v1.5 每次加密应带随机填充，两次结果不应相同")
	}
}

func TestEncryptPasswordTooLong(t *testing.T) {
	if _, err := EncryptPassword(strings.Repeat("a", 54)); err != ErrPasswordTooLong {
		t.Fatalf("err=%v, want ErrPasswordTooLong", err)
	}
	if _, err := EncryptPassword(strings.Repeat("a", 53)); err != nil {
		t.Fatalf("53 字节仍应可加密: %v", err)
	}
}

func TestParseLoginEnvelope(t *testing.T) {
	resp := &http.Response{StatusCode: http.StatusOK, Header: http.Header{}}
	resp.Header.Add("Set-Cookie", "jsessionid=abc123; Path=/; HttpOnly")
	resp.Header.Add("Set-Cookie", "Token=session-token; Path=/")
	longTok := "eyJhbGciOiJIUzI1NiJ9." + base64.RawURLEncoding.EncodeToString([]byte(`{"creator":"ac","expireTime":"1794618107786"}`)) + ".sig"
	body := []byte(`{"code":"0","msg":"success","data":{
		"id":11212514568,"userName":"liziai","fullName":"Haoyi Zhu",
		"token":"` + longTok + `","X-Jwt-Access-Token":"access-token",
		"X-Jwt-Refresh-Token":"refresh-token"}}`)
	sess, err := parseLoginEnvelope("test", resp, body, "desktop-token")
	if err != nil {
		t.Fatal(err)
	}
	if sess.AccessJWT != "access-token" || sess.RefreshJWT != "refresh-token" {
		t.Fatalf("%+v", sess)
	}
	if sess.LongToken != longTok {
		t.Fatalf("long token=%q", sess.LongToken)
	}
	if sess.DesktopToken != "desktop-token" || sess.UserName != "liziai" || sess.UserID != "11212514568" {
		t.Fatalf("%+v", sess)
	}
	if !strings.Contains(sess.Cookie, "Token=session-token") || !strings.Contains(sess.Cookie, "jsessionid=abc123") {
		t.Fatalf("cookie=%q", sess.Cookie)
	}
	if !sess.Valid(time.Now()) {
		t.Fatal("fresh session should be valid")
	}
	if sess.Valid(time.Now().Add(2 * SessionTTL)) {
		t.Fatal("expired session should be invalid")
	}
}

func TestParseLoginEnvelopeBusinessError(t *testing.T) {
	resp := &http.Response{StatusCode: http.StatusOK, Header: http.Header{}}
	body := []byte(`{"code":"1001","msg":"用户名或密码错误"}`)
	if _, err := parseLoginEnvelope("test", resp, body, ""); err == nil {
		t.Fatal("expected error")
	} else if !strings.Contains(err.Error(), "用户名或密码错误") {
		t.Fatalf("err=%v", err)
	}
}

func TestIsDesktopToken(t *testing.T) {
	// {"creator":"ac","expireTime":"1794618107786"}
	acToken := "eyJhbGciOiJIUzI1NiJ9." + base64.RawURLEncoding.EncodeToString([]byte(`{"creator":"ac","expireTime":"1794618107786"}`)) + ".sig"
	if !isDesktopToken(acToken) {
		t.Fatal("AC token should be treated as desktop token")
	}
	// Sugon 会话 JWT：没有 creator/expireTime。
	sugon := "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":{"loginTime":1},"jti":1}`)) + ".sig"
	if isDesktopToken(sugon) {
		t.Fatal("session JWT must not be adopted as desktop token")
	}
	if isDesktopToken("not-a-jwt") || isDesktopToken("") {
		t.Fatal("invalid token should be rejected")
	}
}

func TestLoginData(t *testing.T) {
	sess, err := LoginData([]byte(`{"data":{"token":"t","id":"42","userName":"u"}}`))
	if err == nil {
		t.Fatal("LoginData 期望 data 直接是 token 对象，不应解出嵌套 envelope")
	}
	sess, err = LoginData([]byte(`{"token":"t","id":"42","userName":"u"}`))
	if err != nil || sess.AccessJWT != "t" || sess.UserID != "42" {
		t.Fatalf("sess=%+v err=%v", sess, err)
	}
}

func TestPhoneChallengeExpired(t *testing.T) {
	ch := &PhoneChallenge{Phone: "13800000000", Cookie: "Token=x", CreatedAt: time.Now()}
	if ch.Expired(time.Now(), 5*time.Minute) {
		t.Fatal("fresh challenge should not expire")
	}
	if !ch.Expired(time.Now().Add(6*time.Minute), 5*time.Minute) {
		t.Fatal("challenge should expire after ttl")
	}
	var nilCh *PhoneChallenge
	if !nilCh.Expired(time.Now(), time.Minute) {
		t.Fatal("nil challenge should be treated as expired")
	}
}
