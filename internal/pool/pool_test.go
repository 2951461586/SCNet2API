package pool

import (
	"testing"
	"time"

	"scnet2api/internal/scnet"
)

func acct(id, group string, failures int) *scnet.Account {
	return &scnet.Account{
		ID: id, Name: id, Group: group, Enabled: true, Failures: failures,
		APIKey: &scnet.Credential{APIKey: "sk-" + id},
	}
}

func TestPickSkipsDisabledAndNoKey(t *testing.T) {
	disabled := acct("a", "", 0)
	disabled.Enabled = false
	noKey := acct("b", "", 0)
	noKey.APIKey = nil
	s := New()
	got := s.Pick([]*scnet.Account{disabled, noKey, acct("c", "", 0)}, "", false)
	if got == nil || got.ID != "c" {
		t.Fatalf("got %+v", got)
	}
}

func TestPickRotates(t *testing.T) {
	s := New()
	accounts := []*scnet.Account{acct("a", "", 0), acct("b", "", 0)}
	first := s.Pick(accounts, "", false)
	second := s.Pick(accounts, "", false)
	if first.ID == second.ID {
		t.Fatalf("no rotation: %s %s", first.ID, second.ID)
	}
}

func TestPickGroup(t *testing.T) {
	s := New()
	accounts := []*scnet.Account{acct("a", "g1", 0), acct("b", "g2", 0)}
	if got := s.Pick(accounts, "g2", false); got == nil || got.ID != "b" {
		t.Fatalf("got %+v", got)
	}
	if got := s.Pick(accounts, "missing", false); got != nil {
		t.Fatalf("expected nil, got %+v", got)
	}
}

func TestPickPrefersFewerFailures(t *testing.T) {
	s := New()
	accounts := []*scnet.Account{acct("a", "", 3), acct("b", "", 0)}
	for i := 0; i < 4; i++ {
		if got := s.Pick(accounts, "", false); got.ID != "b" {
			t.Fatalf("picked %s", got.ID)
		}
	}
}

func TestBalanceExhausted(t *testing.T) {
	a := acct("a", "", 0)
	if BalanceExhausted(a) {
		t.Fatal("nil balance should not be exhausted")
	}
	a.Balance = &scnet.Balance{Balance: "0.00", CheckedAt: time.Now().Unix()}
	if !BalanceExhausted(a) {
		t.Fatal("fresh zero balance should be exhausted")
	}
	a.Balance.CheckedAt = time.Now().Add(-2 * BalanceStaleAfter).Unix()
	if BalanceExhausted(a) {
		t.Fatal("stale zero balance should not be exhausted")
	}
	a.Balance = &scnet.Balance{Balance: "12.5", CheckedAt: time.Now().Unix()}
	if BalanceExhausted(a) {
		t.Fatal("positive balance should not be exhausted")
	}
}
