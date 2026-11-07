// SCNet2API 把本机 SCNet（超算互联网）客户端「计算服务」的模型能力，
// 逆向复刻成一个 OpenAI / Anthropic 双协议兼容的 Go 网关。
//
// 复用桌面端已登录的会话（accessToken）自动换取模型 API Key，无需另申请密钥；
// 纯 Go 标准库实现，零外部依赖。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"scnet2api/internal/envfile"
	"scnet2api/internal/scnet"
	"scnet2api/internal/server"
	"scnet2api/internal/store"
)

// version 由构建时注入：-ldflags "-X main.version=1.0.0"
var version = "dev"

func main() {
	// 必须先于任何环境变量读取：flag 默认值直读进程环境。
	envfile.Load()

	var (
		host       = flag.String("host", envOr("SCNET2API_HOST", "127.0.0.1"), "监听地址")
		port       = flag.Int("port", envInt("SCNET2API_PORT", 10088), "监听端口")
		dataPath   = flag.String("data", envOr("SCNET2API_DATA_PATH", ""), "状态文件路径（默认在用户配置目录）")
		clientDir  = flag.String("client-dir", envOr("SCNET2API_CLIENT_DIR", ""), "桌面端数据目录（留空自动探测）")
		importOnly = flag.Bool("import", false, "仅执行一次桌面端登录态导入并完成取 Key 后退出")
		noImport   = flag.Bool("no-import", false, "启动时不自动导入桌面端登录态")
		adminPw    = flag.String("admin-password", envOr("SCNET2API_ADMIN_PASSWORD", ""), "管理密码（非空时覆盖状态文件中的设置）")
		allowOpen  = flag.Bool("allow-insecure", envBool("SCNET2API_ALLOW_INSECURE", false), "允许非回环监听但不设管理密码（不安全）")
		seal       = flag.Bool("seal", false, "把状态文件立即重写为密文后退出（需 "+store.EnvMasterKey+"）")
		sealYes    = flag.Bool("yes", false, "配合 -seal：确认执行不可逆的封存")
		showVer    = flag.Bool("version", false, "打印版本后退出")
	)
	flag.Parse()

	if *showVer {
		fmt.Println("scnet2api", version)
		return
	}

	if *dataPath == "" {
		*dataPath = store.DefaultDataPath()
	}

	st, err := store.Open(*dataPath)
	if err != nil {
		log.Fatalf("打开状态文件失败: %v", err)
	}
	log.Printf("状态文件: %s", st.Path())
	if st.MasterKeySet() {
		log.Printf("状态文件加密: 已启用（AES-256-GCM，密钥指纹 %s，来自 %s）", st.MasterKeyFingerprint(), store.EnvMasterKey)
		if !st.Encrypted() {
			log.Printf("  磁盘上仍是明文：首次保存会自动重写；也可执行 -seal 立即封存。")
		}
	} else {
		log.Printf("⚠ 状态文件未加密：上游会话 / API Key 以明文落盘。")
		log.Printf("  把 %s=$(openssl rand -hex 32) 写进 .env 后重启即可。", store.EnvMasterKey)
	}

	if *seal {
		runSeal(st, *sealYes)
		return
	}

	// 命令行 / 环境变量优先级高于状态文件；设置后立即落盘。
	if *adminPw != "" {
		st.UpdateSettings(func(s *store.Settings) { s.AdminPassword = *adminPw })
		if err := st.Save(); err != nil {
			log.Printf("保存管理密码失败: %v", err)
		} else {
			log.Printf("已启用管理密码（来自命令行 / SCNET2API_ADMIN_PASSWORD）")
		}
	}

	srv := server.New(st)
	srv.Version = version
	srv.ClientDir = *clientDir

	if !*noImport {
		autoImport(srv, *clientDir)
	}
	if token := strings.TrimSpace(os.Getenv("SCNET_DESKTOP_TOKEN")); token != "" {
		acct := &scnet.Account{
			ID: scnet.NewID("acct"), Name: "env-" + scnet.ShortHash(token), Source: "env",
			DesktopToken: token, Enabled: true, Status: "unknown",
		}
		if isNew := st.UpsertAccount(acct); isNew {
			log.Printf("已从 SCNET_DESKTOP_TOKEN 添加账号 %s", acct.Name)
			_ = st.Save()
		}
	}
	if user := strings.TrimSpace(os.Getenv("SCNET_USERNAME")); user != "" {
		if pw := strings.TrimSpace(os.Getenv("SCNET_PASSWORD")); pw != "" {
			acct := &scnet.Account{
				ID: scnet.NewID("acct"), Name: "env-" + user, Source: "env",
				Username: user, Password: pw, Enabled: true, Status: "unknown",
			}
			if isNew := st.UpsertAccount(acct); isNew {
				log.Printf("已从 SCNET_USERNAME / SCNET_PASSWORD 添加账号 %s", acct.Name)
				_ = st.Save()
			}
		}
	}
	if seed := strings.TrimSpace(os.Getenv("SCNET2API_API_KEY")); seed != "" {
		if st.ImportKey(seed, "env") {
			_ = st.Save()
			log.Printf("已从 SCNET2API_API_KEY 导入网关密钥")
		}
	}

	ensureAccounts(srv)
	warnPasswordStorage(st)

	if *importOnly {
		runImport(srv)
		return
	}

	refreshModels(srv)

	// 非回环监听意味着网关已接入局域网 / 公网：管理面必须有密码，数据面必须已有密钥。
	loopback := isLoopbackHost(*host)
	if !loopback {
		if !*allowOpen {
			if st.Settings().AdminPassword == "" {
				log.Fatalf("拒绝在 %s 上无管理密码启动：请设置 SCNET2API_ADMIN_PASSWORD 或 -admin-password，或显式 -allow-insecure", *host)
			}
			if !st.HasKeys() {
				log.Fatalf("拒绝在 %s 上无网关密钥启动：请先在本机控制台创建密钥，或显式 -allow-insecure", *host)
			}
		} else {
			log.Printf("⚠ -allow-insecure：管理面 / 数据面可能无鉴权暴露在 %s", *host)
		}
	}

	addr := net.JoinHostPort(*host, fmt.Sprint(*port))
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 20 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go background(srv, st)
	go func() {
		log.Printf("SCNet2API %s 已启动: http://%s/", version, addr)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("HTTP 服务失败: %v", err)
		}
	}()

	<-stop
	log.Printf("正在关闭…")
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(ctx)
	_ = st.Save()
	log.Printf("已退出")
}

// autoImport 从桌面端 config.json 导入登录态。
func autoImport(srv *server.Server, dir string) {
	added, err := srv.ImportDesktop(dir)
	if err != nil {
		log.Printf("未导入桌面端登录态: %v", err)
		return
	}
	if len(added) == 0 {
		return
	}
	log.Printf("已导入桌面端账号 %d 个", len(added))
}

// ensureAccounts 在启动时补齐会话与模型 Key（并发受限）。
func ensureAccounts(srv *server.Server) {
	accounts := srv.Store.Accounts()
	if len(accounts) == 0 {
		log.Printf("⚠ 当前没有账号：请在控制台「添加账号」粘贴 desktopToken，或先登录桌面端")
		return
	}
	sem := make(chan struct{}, 2)
	var wg sync.WaitGroup
	for _, a := range accounts {
		if !a.Enabled {
			continue
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(id, name string, hasCred bool) {
			defer wg.Done()
			defer func() { <-sem }()
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			if hasCred {
				// 已有 Key 的账号：只在会话过期时静默续期。
				if _, err := srv.EnsureSession(ctx, id, false); err != nil {
					log.Printf("账号 %s 会话续期失败: %v", name, err)
				}
				srv.ProbeAccountAsync(id)
				return
			}
			if err := srv.PrepareAccount(ctx, id); err != nil {
				log.Printf("账号 %s 准备失败: %v", name, err)
				return
			}
			log.Printf("账号 %s 已就绪", name)
		}(a.ID, firstNonEmpty(a.Name, a.UserName, a.ID), a.APIKey != nil && a.APIKey.APIKey != "")
	}
	wg.Wait()
}

// warnPasswordStorage 提醒：保存了账号密码但状态文件未加密。
func warnPasswordStorage(st *store.Store) {
	n := 0
	for _, a := range st.Accounts() {
		if a.Password != "" {
			n++
		}
	}
	if n > 0 && !st.MasterKeySet() {
		log.Printf("⚠ %d 个账号保存了登录密码，但状态文件未加密（明文落盘）", n)
		log.Printf("  建议设置 %s 后执行 -seal -yes；否则请改用 desktopToken 登录。", store.EnvMasterKey)
	}
}

// runImport 完成一次导入 + 取 Key，然后退出（-import）。
func runImport(srv *server.Server) {
	accounts := srv.Store.Accounts()
	if len(accounts) == 0 {
		log.Fatalf("没有可导入的账号：请先在桌面端登录，或用 -client-dir 指定数据目录")
	}
	ok := 0
	for _, a := range accounts {
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		err := srv.PrepareAccount(ctx, a.ID)
		cancel()
		if err != nil {
			log.Printf("账号 %s: %v", a.Name, err)
			continue
		}
		ok++
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if models, err := srv.RefreshModels(ctx); err != nil {
		log.Printf("模型目录刷新失败: %v", err)
	} else {
		log.Printf("模型目录已更新：%d 个模型，默认 %s", len(models), srv.Store.DefaultModel())
	}
	log.Printf("导入完成：%d/%d 个账号可用", ok, len(accounts))
}

// refreshModels 从上游拉取模型目录（失败时保留缓存）。
func refreshModels(srv *server.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	models, err := srv.RefreshModels(ctx)
	if err != nil {
		log.Printf("模型目录刷新失败（沿用缓存 %d 个）: %v", len(srv.Store.Models()), err)
		return
	}
	log.Printf("模型目录已更新：%d 个模型，默认 %s", len(models), srv.Store.DefaultModel())
}

// background 启动会话保活、余额探测与周期落盘。
//
// 两个周期彼此独立：会话 20 分钟续期一次（JWT 30 分钟到期），
// 余额探测按 settings.ProbeMinutes（0 = 关闭）。
func background(srv *server.Server, st *store.Store) {
	sessionTick := time.NewTicker(10 * time.Minute)
	defer sessionTick.Stop()

	probeMinutes := st.Settings().ProbeMinutes
	probeTick := time.NewTicker(time.Duration(maxInt(probeMinutes, 60)) * time.Minute)
	defer probeTick.Stop()

	for {
		select {
		case <-sessionTick.C:
			settings := st.Settings()
			if settings.SessionMinutes > 0 {
				sessionTick.Reset(time.Duration(settings.SessionMinutes) * time.Minute)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			for _, a := range st.Accounts() {
				if !a.Enabled || a.DesktopToken == "" {
					continue
				}
				if _, err := srv.EnsureSession(ctx, a.ID, false); err != nil {
					log.Printf("会话续期失败 %s: %v", a.Name, err)
				}
			}
			cancel()
			_ = st.Save()
		case <-probeTick.C:
			settings := st.Settings()
			if settings.ProbeMinutes > 0 {
				probeTick.Reset(time.Duration(settings.ProbeMinutes) * time.Minute)
				for _, a := range st.Accounts() {
					if a.Enabled {
						srv.ProbeAccountAsync(a.ID)
					}
				}
			}
		}
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// runSeal 把状态文件立即重写为密文。
func runSeal(st *store.Store, yes bool) {
	if !st.MasterKeySet() {
		log.Fatalf("未设置 %s：请先生成 32 字节主密钥", store.EnvMasterKey)
	}
	if !yes {
		log.Fatalf("-seal 会不可逆地加密状态文件；确认后加 -yes 执行")
	}
	if err := st.Seal(); err != nil {
		log.Fatalf("封存失败: %v", err)
	}
	log.Printf("已封存为密文：%s（密钥指纹 %s）", st.Path(), st.MasterKeyFingerprint())
}

// --- 小工具 ---

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	var n int
	if _, err := fmt.Sscanf(raw, "%d", &n); err != nil {
		return fallback
	}
	return n
}

func envBool(key string, fallback bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	return fallback
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" || host == "localhost" {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// defaultDataPath 保持与 store.DefaultDataPath 一致（便于 -h 展示）。
var _ = filepath.Join
