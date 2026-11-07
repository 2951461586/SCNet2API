package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"scnet2api/internal/scnet"
	"scnet2api/internal/store"
)

func tempServer(t *testing.T) *Server {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "data.json"))
	if err != nil {
		t.Fatal(err)
	}
	s := New(st)
	s.Version = "test"
	return s
}

func TestHealthAndModels(t *testing.T) {
	s := tempServer(t)
	h := s.Handler()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"ok"`) {
		t.Fatalf("health %d %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("models %d %s", rec.Code, rec.Body.String())
	}
	var payload struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Data) == 0 || payload.Data[0].ID == "" {
		t.Fatalf("empty catalog: %s", rec.Body.String())
	}
}

func TestAuthRequiredOnceKeyIssued(t *testing.T) {
	s := tempServer(t)
	h := s.Handler()
	s.Store.AddKey("test", "")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}

	key := s.Store.Keys()[0].Key
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Authorization", "Bearer "+key)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestNonLoopbackWithoutKeys(t *testing.T) {
	s := tempServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.RemoteAddr = "192.168.1.10:5555"
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d", rec.Code)
	}
}

func TestAdminPasswordAndSameOrigin(t *testing.T) {
	s := tempServer(t)
	s.Store.UpdateSettings(func(st *store.Settings) { st.AdminPassword = "pw" })
	h := s.Handler()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/api/state", nil)
	req.RemoteAddr = "127.0.0.1:1"
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/admin/api/state", nil)
	req.RemoteAddr = "127.0.0.1:1"
	req.Header.Set("X-Admin-Password", "pw")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d %s", rec.Code, rec.Body.String())
	}

	// 跨站写请求被拒绝。
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/admin/api/settings", strings.NewReader("{}"))
	req.RemoteAddr = "127.0.0.1:1"
	req.Header.Set("X-Admin-Password", "pw")
	req.Header.Set("Origin", "https://evil.example")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", rec.Code)
	}
}

func TestCountTokens(t *testing.T) {
	s := tempServer(t)
	rec := httptest.NewRecorder()
	body := `{"model":"SCNet-Max","messages":[{"role":"user","content":"hello world"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/messages/count_tokens", strings.NewReader(body))
	req.RemoteAddr = "127.0.0.1:1"
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d %s", rec.Code, rec.Body.String())
	}
	var payload struct {
		InputTokens int `json:"input_tokens"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.InputTokens <= 0 {
		t.Fatalf("tokens=%d", payload.InputTokens)
	}
}

func TestCORS(t *testing.T) {
	s := tempServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.RemoteAddr = "127.0.0.1:1"
	req.Header.Set("Origin", "http://localhost:3000")
	s.Handler().ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:3000" {
		t.Fatalf("cors=%q", got)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodOptions, "/v1/chat/completions", nil)
	req.RemoteAddr = "127.0.0.1:1"
	req.Header.Set("Origin", "http://localhost:3000")
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("preflight=%d", rec.Code)
	}
}

func TestImportDesktop(t *testing.T) {
	s := tempServer(t)
	dir := t.TempDir()
	writeFile := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeFile("config.json", `{"accessToken":"token-1","userInfo":{"id":"42","userName":"tester"}}`)
	added, err := s.ImportDesktop(dir)
	if err != nil || len(added) != 1 {
		t.Fatalf("added=%v err=%v", added, err)
	}
	if _, err := s.ImportDesktop(dir); err != nil {
		t.Fatal(err)
	}
	if s.Store.AccountCount() != 1 {
		t.Fatalf("count=%d", s.Store.AccountCount())
	}
}

func TestMaskPhone(t *testing.T) {
	cases := map[string]string{
		"13800001234": "138****1234",
		"1234567":     "***",
		"":            "***",
	}
	for in, want := range cases {
		if got := maskPhone(in); got != want {
			t.Fatalf("maskPhone(%q)=%q, want %q", in, got, want)
		}
	}
}

func TestPhoneChallengePrune(t *testing.T) {
	s := tempServer(t)
	s.phones["fresh"] = &scnet.PhoneChallenge{Phone: "13800000000", Cookie: "Token=x", CreatedAt: time.Now()}
	s.phones["stale"] = &scnet.PhoneChallenge{Phone: "13900000000", Cookie: "Token=y", CreatedAt: time.Now().Add(-10 * time.Minute)}
	s.phoneMu.Lock()
	s.prunePhoneChallengesLocked(time.Now())
	s.phoneMu.Unlock()
	if _, ok := s.phones["fresh"]; !ok {
		t.Fatal("fresh challenge removed")
	}
	if _, ok := s.phones["stale"]; ok {
		t.Fatal("stale challenge kept")
	}
}

func TestAddAccountValidation(t *testing.T) {
	s := tempServer(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/api/accounts",
		strings.NewReader(`{"action":"add"}`))
	req.RemoteAddr = "127.0.0.1:1"
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d %s", rec.Code, rec.Body.String())
	}
}

func TestLoginModeOf(t *testing.T) {
	token := &scnet.Account{DesktopToken: "t"}
	if got := loginModeOf(token); got != "token" {
		t.Fatalf("got %q", got)
	}
	withPw := &scnet.Account{DesktopToken: "t", Username: "u", Password: "p"}
	if got := loginModeOf(withPw); got != "token+password" {
		t.Fatalf("got %q", got)
	}
	phone := &scnet.Account{Source: "phone", Username: "13800000000"}
	if got := loginModeOf(phone); got != "phone" {
		t.Fatalf("got %q", got)
	}
}
