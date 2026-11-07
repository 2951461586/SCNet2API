// Command probe 是 SCNet 上游的离线诊断工具。
//
// 用法：
//
//	go run ./cmd/probe -usage                 # 登录 + 余额 + 模型目录
//	go run ./cmd/probe -prompt "hello"        # 真实调用一次
//	go run ./cmd/probe -prompt "hi" -stream   # 流式调用
//	go run ./cmd/probe -token <desktopToken>  # 直接验证某个 desktopToken
//	go run ./cmd/probe -key <apiKey>          # 直接验证某个模型 Key
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"scnet2api/internal/scnet"
)

func main() {
	var (
		dir    = flag.String("dir", "", "scnet-client 数据目录（默认自动探测）")
		token  = flag.String("token", "", "desktopToken（覆盖 config.json）")
		key    = flag.String("key", "", "模型 API Key（跳过登录与创建）")
		prompt = flag.String("prompt", "", "发送一条真实对话（留空只做只读诊断）")
		model  = flag.String("model", scnet.DefaultModel, "模型 ID")
		proto  = flag.String("proto", "chat", "协议：chat / responses / anthropic")
		stream = flag.Bool("stream", false, "流式输出")
		search = flag.String("search", "", "调用一次联网搜索")
		usage  = flag.Bool("usage", false, "只读诊断：登录 + 余额 + 模型目录（默认行为）")
	)
	_ = *usage
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	client := scnet.NewClient()

	cred := &scnet.Credential{
		APIKey:           strings.TrimSpace(*key),
		BaseURL:          scnet.LLMBase,
		AnthropicBaseURL: scnet.AnthropicBase,
	}
	var sess *scnet.Session

	if cred.APIKey == "" {
		desktopToken := strings.TrimSpace(*token)
		if desktopToken == "" {
			cfg, path, err := loadDesktopToken(*dir)
			if err != nil {
				fatalf("读取桌面端登录态失败: %v", err)
			}
			desktopToken = cfg.Token
			fmt.Printf("桌面端配置: %s\n账号: %s (%s)\n", path, cfg.UserName, cfg.UserID)
		}
		var err error
		sess, err = client.LoginToken(ctx, desktopToken)
		if err != nil {
			fatalf("登录失败: %v", err)
		}
		fmt.Printf("登录成功: %s (%s)\n", sess.UserName, sess.UserID)

		probe, err := client.ProbeAccount(ctx, sess)
		if err != nil {
			fmt.Printf("账号探测失败: %v\n", err)
		} else {
			printProbe(probe)
		}
		cred2, err := client.EnsureCredential(ctx, sess)
		if err != nil {
			fatalf("获取模型 Key 失败: %v", err)
		}
		cred = cred2
	}
	fmt.Printf("模型 Key: %s（来源 %s）\n", scnet.Mask(cred.APIKey), cred.Source)
	fmt.Printf("BaseURL: %s\nAnthropic: %s\n", cred.BaseURL, cred.AnthropicBaseURL)

	models, err := client.ListRemoteModels(ctx, cred)
	if err != nil {
		fmt.Printf("模型网关验活失败: %v\n", err)
	} else {
		fmt.Printf("模型网关可用：%d 个模型\n", len(models))
	}

	if *search != "" {
		searchKey, err := client.EnsureSearchKey(ctx, sess, "")
		if err != nil {
			fatalf("获取联网搜索 Key 失败: %v", err)
		}
		res, err := client.Search(ctx, searchKey, scnet.SearchRequest{Query: *search, Count: 5, Summary: true})
		if err != nil {
			fatalf("联网搜索失败: %v", err)
		}
		fmt.Printf("联网搜索：%d 条结果\n", len(res.Items))
		for _, it := range res.Items {
			fmt.Printf("- %s\n  %s\n", it.Title, it.URL)
		}
	}

	if *prompt == "" {
		return
	}

	body := map[string]any{"model": *model, "stream": *stream}
	switch strings.ToLower(*proto) {
	case "anthropic":
		body["max_tokens"] = 512
		body["messages"] = []map[string]any{{"role": "user", "content": *prompt}}
	case "responses":
		body["input"] = *prompt
	default:
		body["messages"] = []map[string]any{{"role": "user", "content": *prompt}}
	}
	raw, _ := json.Marshal(body)

	var resp *io.ReadCloser
	switch strings.ToLower(*proto) {
	case "anthropic":
		r, err := client.Messages(ctx, cred, raw, nil)
		if err != nil {
			fatalf("调用失败: %v", err)
		}
		resp = &r.Body
	case "responses":
		r, err := client.Responses(ctx, cred, raw, nil)
		if err != nil {
			fatalf("调用失败: %v", err)
		}
		resp = &r.Body
	default:
		r, err := client.Chat(ctx, cred, raw, nil)
		if err != nil {
			fatalf("调用失败: %v", err)
		}
		resp = &r.Body
	}
	defer (*resp).Close()

	if *stream {
		sc := bufio.NewScanner(*resp)
		sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
		for sc.Scan() {
			fmt.Println(sc.Text())
		}
		if err := sc.Err(); err != nil {
			fatalf("读取流失败: %v", err)
		}
		return
	}
	out, _ := io.ReadAll(io.LimitReader(*resp, 8<<20))
	fmt.Printf("\n响应:\n%s\n", string(out))
}

type desktopConfig struct {
	Token    string
	UserName string
	UserID   string
}

func loadDesktopToken(dir string) (desktopConfig, string, error) {
	path, err := findConfig(dir)
	if err != nil {
		return desktopConfig{}, "", err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return desktopConfig{}, path, err
	}
	var cfg struct {
		AccessToken string `json:"accessToken"`
		UserInfo    struct {
			ID       any    `json:"id"`
			UserName string `json:"userName"`
		} `json:"userInfo"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return desktopConfig{}, path, err
	}
	if cfg.AccessToken == "" {
		return desktopConfig{}, path, fmt.Errorf("config.json 中没有 accessToken（请先在桌面端登录）")
	}
	id := ""
	switch v := cfg.UserInfo.ID.(type) {
	case string:
		id = v
	case float64:
		id = fmt.Sprintf("%.0f", v)
	}
	return desktopConfig{Token: cfg.AccessToken, UserName: cfg.UserInfo.UserName, UserID: id}, path, nil
}

func findConfig(dir string) (string, error) {
	candidates := []string{dir}
	if appData := os.Getenv("APPDATA"); appData != "" {
		candidates = append(candidates, filepath.Join(appData, "scnet-client"))
	}
	candidates = append(candidates, os.Getenv("SCNET2API_CLIENT_DIR"))
	for _, candidate := range candidates {
		if strings.TrimSpace(candidate) == "" {
			continue
		}
		path := candidate
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			path = filepath.Join(candidate, "config.json")
		}
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("未找到 scnet-client 的 config.json")
}

func printProbe(p *scnet.Probe) {
	if p.User != nil {
		fmt.Printf("用户: %s (%s)\n", p.User.UserName, p.User.ID)
	}
	if p.Balance != nil {
		fmt.Printf("余额: %s %s · 欠费=%v · 模型服务=%v\n",
			p.Balance.Balance, p.Balance.Currency, p.Balance.Unpaid, p.Balance.ModelReady)
		if p.Balance.AccountID != "" {
			fmt.Printf("团队账号: %s / %s / %s\n", p.Balance.AccountID, p.Balance.GroupName, p.Balance.ClusterName)
		}
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
