package scnet

import (
	"encoding/json"
	"testing"
)

func TestExtractKey(t *testing.T) {
	cases := map[string]string{
		`"sk-plain"`:                            "sk-plain",
		`{"apiKey":"sk-obj"}`:                   "sk-obj",
		`{"data":{"apiKey":"sk-nested"}}`:       "sk-nested",
		`{"apiKeyName":"x"}`:                    "",
		`{"data":"sk-string"}`:                  "sk-string",
		`null`:                                  "",
		`{"key":"sk-key","secret":"sk-secret"}`: "sk-key",
	}
	for raw, want := range cases {
		if got := extractKey(json.RawMessage(raw)); got != want {
			t.Fatalf("%s => %q, want %q", raw, got, want)
		}
	}
}

func TestPrimaryClusterUser(t *testing.T) {
	rows := []ClusterUser{
		{AccountID: "1", GroupID: "g1", CreateUser: "u1", MemberType: "Leader", Status: "Normal"},
	}
	cu, err := primaryClusterUser(rows)
	if err != nil || cu.AccountID != "1" {
		t.Fatalf("cu=%+v err=%v", cu, err)
	}

	disabled := []ClusterUser{{AccountID: "1", GroupID: "g1", CreateUser: "u1", MemberType: "Leader", Status: "disable"}}
	if _, err := primaryClusterUser(disabled); err == nil {
		t.Fatal("expected disabled error")
	}

	ambiguous := []ClusterUser{
		{AccountID: "1", GroupID: "g1", CreateUser: "u1", MemberType: "Leader"},
		{AccountID: "2", GroupID: "g2", CreateUser: "u2", MemberType: "Leader"},
	}
	if _, err := primaryClusterUser(ambiguous); err == nil {
		t.Fatal("expected ambiguous error")
	}

	if _, err := primaryClusterUser(nil); err == nil {
		t.Fatal("expected empty error")
	}
}

func TestDecodeCredential(t *testing.T) {
	raw := json.RawMessage(`{"apiKey":"sk-1","baseUrl":"https://api.scnet.cn/api/llm/v1","anthropicBaseUrl":"https://api.scnet.cn/api/llm/anthropic","model":"MiniMax-M2.5"}`)
	cred := decodeCredential(raw)
	if cred.APIKey != "sk-1" || cred.DefaultModel != "MiniMax-M2.5" {
		t.Fatalf("%+v", cred)
	}
	if cred.BaseURL == "" || cred.AnthropicBaseURL == "" {
		t.Fatalf("base urls missing: %+v", cred)
	}
}

func TestHTTPErrorClassification(t *testing.T) {
	balance := &HTTPError{Status: 402, Body: []byte(`{"error":{"message":"Insufficient Balance"}}`)}
	if !balance.BalanceExhausted() {
		t.Fatal("402 should be balance exhausted")
	}
	auth := &HTTPError{Status: 401, Body: []byte(`{"error":{"code":"invalid_api_key"}}`)}
	if !auth.AuthFailed() || auth.Code() != "invalid_api_key" {
		t.Fatalf("auth classification: %v %q", auth.AuthFailed(), auth.Code())
	}
	bad := &HTTPError{Status: 400, Body: []byte(`{"error":{"message":"messages is required"}}`)}
	if bad.Retryable() {
		t.Fatal("400 should not be retryable")
	}
	if !IsTransient(&HTTPError{Status: 503}) {
		t.Fatal("503 should be transient")
	}
}

func TestModelSemantics(t *testing.T) {
	m := Model{ID: "SCNet-Max", PriceLabel: "free", Input: []string{"text", "image"},
		Protocols: []string{"OPENAI_CHAT", "ANTHROPIC"}}
	if !m.IsFree() || !m.Supports("anthropic") || !m.SupportsImage() {
		t.Fatalf("%+v", m)
	}
	if m.Supports("OPENAI_RESPONSES") {
		t.Fatal("unexpected protocol")
	}
}
