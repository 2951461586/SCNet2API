package registry

import (
	"testing"

	"scnet2api/internal/scnet"
)

func catalog() []scnet.Model {
	return []scnet.Model{
		{ID: "SCNet-Max", Name: "SCNet-Max", Free: true, PriceLabel: "free"},
		{ID: "DeepSeek-V4.1-Flash", Name: "DeepSeek V4.1 Flash"},
	}
}

func TestResolveExact(t *testing.T) {
	m := Resolve(catalog(), nil, "deepseek-v4.1-flash", "SCNet-Max")
	if m.ID != "DeepSeek-V4.1-Flash" {
		t.Fatalf("got %q", m.ID)
	}
}

func TestResolveAliases(t *testing.T) {
	aliases := map[string]string{"my-model": "DeepSeek-V4.1-Flash"}
	if m := Resolve(catalog(), aliases, "my-model", "SCNet-Max"); m.ID != "DeepSeek-V4.1-Flash" {
		t.Fatalf("custom alias got %q", m.ID)
	}
	if m := Resolve(catalog(), nil, "gpt-4o", "SCNet-Max"); m.ID != "SCNet-Max" {
		t.Fatalf("builtin alias got %q", m.ID)
	}
	if m := Resolve(catalog(), nil, "openai/gpt-4", "SCNet-Max"); m.ID != "SCNet-Max" {
		t.Fatalf("prefixed alias got %q", m.ID)
	}
}

func TestResolveFallback(t *testing.T) {
	if m := Resolve(catalog(), nil, "totally-unknown", "SCNet-Max"); m.ID != "SCNet-Max" {
		t.Fatalf("fallback got %q", m.ID)
	}
	if m := Resolve(nil, nil, "x", ""); m.ID != scnet.DefaultModel {
		t.Fatalf("empty catalog got %q", m.ID)
	}
}

func TestListIncludesAliases(t *testing.T) {
	models := List(catalog(), map[string]string{"claude-3-5-sonnet": "SCNet-Max"})
	if len(models) != 3 {
		t.Fatalf("len=%d", len(models))
	}
	if models[2].ID != "claude-3-5-sonnet" {
		t.Fatalf("alias not appended: %+v", models[2])
	}
}
