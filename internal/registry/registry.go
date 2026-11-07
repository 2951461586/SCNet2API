// Package registry 维护对外暴露的模型清单与别名解析。
//
// 模型目录由上游 /acx/llm/api/console/model 动态下发；本包只做缓存快照上的
// 解析与别名扩展，不承担网络请求。
package registry

import (
	"strings"

	"scnet2api/internal/scnet"
)

// Resolve 把用户传入的模型名解析为目录中的模型。
//
// 依次尝试：去前缀 → 精确 ID → 自定义别名 → 内置别名 → 包含匹配 →
// 回落到 defaultID → 回落到目录第一个模型。
//
// 无法识别时不报错而是回落：任意客户端（Claude Code / Cline / OpenAI SDK）
// 都能用自己习惯的模型名开箱即用。
func Resolve(catalog []scnet.Model, aliases map[string]string, name, defaultID string) scnet.Model {
	n := normalize(name)
	if n != "" {
		if m, ok := lookup(catalog, n); ok {
			return m
		}
		if target, ok := lookupAlias(aliases, n); ok {
			if m, ok := lookup(catalog, target); ok {
				return m
			}
		}
		if target, ok := builtinAliases[n]; ok {
			if m, ok := lookup(catalog, target); ok {
				return m
			}
		}
		for _, m := range catalog {
			if strings.Contains(strings.ToLower(m.ID), n) {
				return m
			}
		}
		for _, m := range catalog {
			if n == normalize(m.Name) {
				return m
			}
		}
	}
	if m, ok := lookup(catalog, normalize(defaultID)); ok {
		return m
	}
	if len(catalog) > 0 {
		return catalog[0]
	}
	return scnet.DefaultModelEntry()
}

// List 返回对外模型清单（含自定义别名）。
func List(catalog []scnet.Model, aliases map[string]string) []scnet.Model {
	out := make([]scnet.Model, len(catalog))
	copy(out, catalog)
	for alias, target := range aliases {
		alias = strings.TrimSpace(alias)
		if alias == "" {
			continue
		}
		if m, ok := lookup(catalog, normalize(target)); ok {
			m.ID = alias
			m.Name = alias + " → " + m.Name
			out = append(out, m)
		}
	}
	return out
}

// Find 返回 ID 精确匹配的模型。
func Find(catalog []scnet.Model, id string) (scnet.Model, bool) {
	return lookup(catalog, normalize(id))
}

// builtinAliases 是常见客户端模型名到 SCNet 模型的映射。
//
// 默认只指向免费模型 SCNet-Max；用户可在控制台覆盖为任意目标。
var builtinAliases = map[string]string{
	"scnet":             scnet.DefaultModel,
	"scnet-max":         scnet.DefaultModel,
	"default":           scnet.DefaultModel,
	"gpt-3.5-turbo":     scnet.DefaultModel,
	"gpt-4":             scnet.DefaultModel,
	"gpt-4o":            scnet.DefaultModel,
	"gpt-4o-mini":       scnet.DefaultModel,
	"gpt-4.1":           scnet.DefaultModel,
	"gpt-5":             scnet.DefaultModel,
	"claude-3-5-sonnet": scnet.DefaultModel,
	"claude-sonnet-4":   scnet.DefaultModel,
	"claude-3-haiku":    scnet.DefaultModel,
	"deepseek-chat":     scnet.DefaultModel,
	"deepseek-reasoner": scnet.DefaultModel,
	"glm-4-flash":       scnet.DefaultModel,
	"qwen":              scnet.DefaultModel,
	"o3":                scnet.DefaultModel,
}

func normalize(name string) string {
	n := strings.TrimSpace(strings.ToLower(name))
	for _, prefix := range []string{"scnet/", "scnet:", "openai/", "openai:", "anthropic/", "anthropic:"} {
		if strings.HasPrefix(n, prefix) {
			n = strings.TrimSpace(strings.TrimPrefix(n, prefix))
			break
		}
	}
	return n
}

func lookup(catalog []scnet.Model, id string) (scnet.Model, bool) {
	if id == "" {
		return scnet.Model{}, false
	}
	for _, m := range catalog {
		if strings.EqualFold(m.ID, id) {
			return m, true
		}
	}
	return scnet.Model{}, false
}

func lookupAlias(aliases map[string]string, key string) (string, bool) {
	for k, v := range aliases {
		if strings.EqualFold(strings.TrimSpace(k), key) {
			return normalize(v), true
		}
	}
	return "", false
}
