package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"scnet2api/internal/scnet"
)

func tempStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	st, err := Open(filepath.Join(dir, "data.json"))
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestUpsertAndMerge(t *testing.T) {
	st := tempStore(t)
	a := &scnet.Account{ID: "a1", Name: "first", Group: "g", Enabled: true, DesktopToken: "tok", UserID: "u1"}
	if !st.UpsertAccount(a) {
		t.Fatal("expected new account")
	}
	st.MarkAccountResult("a1", false, "boom")
	st.UpdateAccount("a1", func(a *scnet.Account) {
		a.Balance = &scnet.Balance{Balance: "0.00"}
	})

	// 同 UserID 重新导入：运行态保留，空字段回落。
	b := &scnet.Account{ID: "a2", UserID: "u1", Name: "", Enabled: true}
	if st.UpsertAccount(b) {
		t.Fatal("expected merge, not new")
	}
	got := st.Account("a1")
	if got == nil || got.ID != "a1" {
		t.Fatalf("account=%+v", got)
	}
	if got.Failures != 1 || got.Balance == nil {
		t.Fatalf("runtime state lost: %+v", got)
	}
	if got.Name != "first" || got.DesktopToken != "tok" {
		t.Fatalf("identity not filled: %+v", got)
	}
	if st.AccountCount() != 1 {
		t.Fatalf("count=%d", st.AccountCount())
	}
}

func TestNextAccountGroup(t *testing.T) {
	st := tempStore(t)
	st.UpsertAccount(&scnet.Account{ID: "a", Group: "g1", Enabled: true, APIKey: &scnet.Credential{APIKey: "k1"}})
	st.UpsertAccount(&scnet.Account{ID: "b", Group: "g2", Enabled: true, APIKey: &scnet.Credential{APIKey: "k2"}})
	if a := st.NextAccountGroup("g2", false); a == nil || a.ID != "b" {
		t.Fatalf("got %+v", a)
	}
	if a := st.NextAccountGroup("nope", false); a != nil {
		t.Fatalf("expected nil, got %+v", a)
	}
	if got := st.Groups(); len(got) != 2 {
		t.Fatalf("groups=%v", got)
	}
}

func TestKeys(t *testing.T) {
	st := tempStore(t)
	if st.HasKeys() {
		t.Fatal("empty store should have no keys")
	}
	k := st.AddKey("name", "g")
	if !st.HasKeys() || !st.ValidKey(k.Key) {
		t.Fatal("key not valid")
	}
	if st.KeyGroup(k.Key) != "g" {
		t.Fatalf("group=%q", st.KeyGroup(k.Key))
	}
	st.TouchKey(k.Key)
	if st.Keys()[0].Requests != 1 {
		t.Fatal("touch not recorded")
	}
	st.UpdateKey(k.Key, func(k *APIKey) { k.Enabled = false })
	if st.ValidKey(k.Key) {
		t.Fatal("disabled key should be invalid")
	}
	if !st.RemoveKey(k.Key) {
		t.Fatal("remove failed")
	}
	if len(st.Keys()) != 0 {
		t.Fatal("key not removed")
	}
}

func TestLogsAndStats(t *testing.T) {
	st := tempStore(t)
	for i := 0; i < 5; i++ {
		e := LogEntry{Time: int64(i + 1), Status: 200, TokensIn: 10, TokensOut: 20, OutputLen: 30}
		st.AppendLog(e)
		st.AddStats(e)
	}
	if got := len(st.Logs(3)); got != 3 {
		t.Fatalf("logs=%d", got)
	}
	stats := st.Stats()
	if stats.TotalRequests != 5 || stats.TotalTokensOut != 100 {
		t.Fatalf("stats=%+v", stats)
	}
	st.ResetStats()
	if st.Stats().TotalRequests != 0 {
		t.Fatalf("reset failed: %+v", st.Stats())
	}
}

func TestLogPrune(t *testing.T) {
	st := tempStore(t)
	st.UpdateSettings(func(s *Settings) { s.LogKeep = 2 })
	for i := 0; i < 5; i++ {
		st.AppendLog(LogEntry{Time: int64(i + 1)})
	}
	logs := st.Logs(0)
	if len(logs) != 2 || logs[0].Time != 4 || logs[1].Time != 5 {
		t.Fatalf("prune failed: %+v", logs)
	}
}

func TestSaveReloadAndSeal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data.json")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	st.UpsertAccount(&scnet.Account{ID: "a", Name: "n", Enabled: true, DesktopToken: "secret-token"})
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "secret-token") {
		t.Fatal("expected plaintext before seal")
	}

	t.Setenv(EnvMasterKey, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	st2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := st2.Seal(); err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if isSealed(raw) == false || strings.Contains(string(raw), "secret-token") {
		t.Fatal("seal did not encrypt")
	}
	st3, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if a := st3.Account("a"); a == nil || a.DesktopToken != "secret-token" {
		t.Fatalf("reload after seal failed: %+v", a)
	}
}

func TestSettingsDefaults(t *testing.T) {
	st := tempStore(t)
	s := st.Settings()
	if s.MaxRetries <= 0 || s.LogKeep <= 0 || s.ModelAliases == nil {
		t.Fatalf("defaults not applied: %+v", s)
	}
	st.UpdateSettings(func(s *Settings) { s.CORSOrigin = "*" })
	st.Save()
	reopened, err := Open(st.Path())
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Settings().CORSOrigin != "*" {
		t.Fatal("settings not persisted")
	}
}
