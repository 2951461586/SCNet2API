package store

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"scnet2api/internal/pool"
)

// EnvMasterKey 是状态文件加密主密钥的环境变量名。
const EnvMasterKey = "SCNET2API_MASTER_KEY"

// sealMagic 是密文文件头，用于区分明文状态文件。
var sealMagic = []byte("SCN2SEAL1")

// defaultDataPath 返回默认状态文件路径。
func defaultDataPath() string {
	if dir, err := os.UserConfigDir(); err == nil && dir != "" {
		return filepath.Join(dir, "scnet2api", "data.json")
	}
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "scnet2api-data.json")
	}
	return "scnet2api-data.json"
}

// masterKeyFromEnv 解析主密钥：64 位 hex 或 base64（32 字节）。
func masterKeyFromEnv() ([]byte, error) {
	raw := strings.TrimSpace(os.Getenv(EnvMasterKey))
	if raw == "" {
		return nil, nil
	}
	if b, err := hex.DecodeString(raw); err == nil && len(b) == 32 {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(raw); err == nil && len(b) == 32 {
		return b, nil
	}
	sum := sha256.Sum256([]byte(raw))
	return sum[:], nil
}

// Open 打开（或初始化）状态文件。
func Open(path string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		path = defaultDataPath()
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
		return nil, err
	}
	key, err := masterKeyFromEnv()
	if err != nil {
		return nil, err
	}
	s := &Store{
		path:      abs,
		st:        &State{Settings: DefaultSettings()},
		sched:     NewScheduler(),
		statsPath: derivePath(abs, "-stats.json"),
		logsPath:  derivePath(abs, "-logs.jsonl"),
		masterKey: key,
	}
	s.logs = newLogStore(s.logsPath)
	if err := s.load(); err != nil {
		return nil, err
	}
	if err := s.loadSidecars(); err != nil {
		return nil, err
	}
	if s.st.Settings.ModelAliases == nil {
		s.st.Settings.ModelAliases = map[string]string{}
	}
	s.applyDefaults()
	return s, nil
}

// derivePath 把 data.json 派生为 data-logs.jsonl / data-stats.json。
func derivePath(path, suffix string) string {
	ext := filepath.Ext(path)
	base := strings.TrimSuffix(path, ext)
	if ext == "" {
		ext = ".json"
	}
	return base + suffix
}

// applyDefaults 补齐缺失的设置项（升级兼容）。
func (s *Store) applyDefaults() {
	def := DefaultSettings()
	set := &s.st.Settings
	if set.RequestTimeout <= 0 {
		set.RequestTimeout = def.RequestTimeout
	}
	if set.MaxRetries <= 0 {
		set.MaxRetries = def.MaxRetries
	}
	if set.LogKeep <= 0 {
		set.LogKeep = def.LogKeep
	}
	if set.ProbeMinutes < 0 {
		set.ProbeMinutes = def.ProbeMinutes
	}
	if set.SessionMinutes <= 0 {
		set.SessionMinutes = def.SessionMinutes
	}
	if set.SearchKeyName == "" {
		set.SearchKeyName = def.SearchKeyName
	}
	if set.ModelAliases == nil {
		set.ModelAliases = map[string]string{}
	}
	if s.st.DefaultModel == "" {
		s.st.DefaultModel = "SCNet-Max"
	}
}

// load 读取主状态文件（兼容明文 / 密文）。
func (s *Store) load() error {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if s.masterKey != nil {
				s.encrypted = true
			}
			return nil
		}
		return err
	}
	if len(raw) == 0 {
		return nil
	}
	plain := raw
	if isSealed(raw) {
		if s.masterKey == nil {
			return fmt.Errorf("状态文件已加密，但未设置 %s", EnvMasterKey)
		}
		data, err := openSealed(s.masterKey, raw)
		if err != nil {
			return fmt.Errorf("解密状态文件失败: %w", err)
		}
		plain = data
		s.encrypted = true
	}
	var st State
	if err := json.Unmarshal(plain, &st); err != nil {
		var legacy legacyState
		if err2 := json.Unmarshal(plain, &legacy); err2 != nil {
			return fmt.Errorf("状态文件解析失败: %w", err)
		}
		st = State{
			Accounts: legacy.Accounts, Keys: legacy.Keys, Settings: legacy.Settings,
			Models: legacy.Models, DefaultModel: legacy.DefaultModel,
			ModelsUpdated: legacy.ModelsUpdated, Stats: legacy.Stats, Logs: legacy.Logs,
		}
	}
	s.st = &st
	s.lastSaved = plain
	return nil
}

// loadSidecars 读取日志与统计旁路文件。
func (s *Store) loadSidecars() error {
	if s.st.Stats.StartedAt == 0 {
		s.st.Stats.StartedAt = now()
	}
	if data, err := os.ReadFile(s.statsPath); err == nil && len(data) > 0 {
		var st Stats
		if json.Unmarshal(data, &st) == nil {
			if st.StartedAt == 0 {
				st.StartedAt = s.st.Stats.StartedAt
			}
			s.st.Stats = st
		}
	}
	if err := s.logs.load(); err != nil {
		return err
	}
	s.st.Logs = parseLogLines(s.logs.pending)
	s.logs.pending = nil
	return nil
}

// Path 返回主状态文件路径。
func (s *Store) Path() string { return s.path }

// MasterKeySet 报告是否配置了主密钥。
func (s *Store) MasterKeySet() bool { return s.masterKey != nil }

// MasterKeyFingerprint 返回主密钥指纹（前 8 字节 hex）。
func (s *Store) MasterKeyFingerprint() string {
	if s.masterKey == nil {
		return ""
	}
	return hex.EncodeToString(s.masterKey[:8])
}

// Encrypted 报告上次读取时文件是否为密文。
func (s *Store) Encrypted() bool { return s.encrypted }

// Save 把状态写入磁盘（原子替换 + 内容未变则跳过）。
func (s *Store) Save() error {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()

	s.mu.RLock()
	plain, err := json.MarshalIndent(s.st, "", "  ")
	s.mu.RUnlock()
	if err != nil {
		return err
	}
	if s.lastSaved != nil && string(s.lastSaved) == string(plain) {
		return nil
	}
	payload := plain
	encrypted := false
	if s.masterKey != nil {
		payload, err = seal(s.masterKey, plain)
		if err != nil {
			return err
		}
		encrypted = true
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, payload, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	s.lastSaved = plain
	s.encrypted = encrypted
	s.savesTotal.Add(1)
	s.savedBytes.Add(int64(len(plain)))

	if s.statsDirty {
		s.saveStats()
	}
	return nil
}

// saveStats 写入统计旁路文件（调用方持 saveMu）。
func (s *Store) saveStats() {
	s.mu.RLock()
	raw, err := json.MarshalIndent(s.st.Stats, "", "  ")
	s.mu.RUnlock()
	if err != nil {
		return
	}
	_ = os.WriteFile(s.statsPath, raw, 0o600)
	s.statsDirty = false
}

// SaveStats 显式落盘统计。
func (s *Store) SaveStats() {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	s.saveStats()
}

// isSealed 判断文件是否为本包的密文格式。
func isSealed(raw []byte) bool {
	return len(raw) > len(sealMagic) && string(raw[:len(sealMagic)]) == string(sealMagic)
}

// seal 用 AES-256-GCM 加密。
func seal(key, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := append([]byte{}, sealMagic...)
	out = append(out, nonce...)
	return gcm.Seal(out, nonce, plain, sealMagic), nil
}

// openSealed 解密。
func openSealed(key, raw []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(raw) < len(sealMagic)+gcm.NonceSize() {
		return nil, errors.New("密文长度不足")
	}
	nonce := raw[len(sealMagic) : len(sealMagic)+gcm.NonceSize()]
	body := raw[len(sealMagic)+gcm.NonceSize():]
	return gcm.Open(nil, nonce, body, sealMagic)
}

// now 是统一时间源（秒）。
func now() int64 { return timeNow().Unix() }

// Seal 立即把状态文件重写为密文。
//
// 即使主文件内容未变也强制写盘（清掉 lastSaved 的“无变化跳过”）。
func (s *Store) Seal() error {
	s.saveMu.Lock()
	s.lastSaved = nil
	s.saveMu.Unlock()
	if err := s.Save(); err != nil {
		return err
	}
	if !s.Encrypted() {
		return errors.New("状态文件仍为明文，请检查主密钥")
	}
	return nil
}

// NewScheduler 返回号池调度器。
func NewScheduler() *pool.Scheduler { return pool.New() }

// timeNow 是统一时间源。
func timeNow() time.Time { return time.Now() }

// logStore 管理 append-only 的 JSONL 请求日志。
type logStore struct {
	path    string
	mu      sync.Mutex
	pending []string
}

func newLogStore(path string) *logStore { return &logStore{path: path} }

// load 读取全部日志（启动时调用；文件不存在视为空）。
func (l *logStore) load() error {
	f, err := os.Open(l.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 8<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		l.pending = append(l.pending, line)
	}
	return sc.Err()
}

// parseLogs 把日志行解析为 LogEntry 列表。
func parseLogLines(lines []string) []LogEntry {
	out := make([]LogEntry, 0, len(lines))
	for _, line := range lines {
		var e LogEntry
		if json.Unmarshal([]byte(line), &e) == nil {
			out = append(out, e)
		}
	}
	return out
}

// append 追加一条日志。
func (l *logStore) append(e LogEntry) error {
	raw, err := json.Marshal(e)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(raw, '\n')); err != nil {
		return err
	}
	return nil
}

// rewrite 用给定日志重写文件（用于裁剪）。
func (l *logStore) rewrite(entries []LogEntry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	var b strings.Builder
	for _, e := range entries {
		raw, err := json.Marshal(e)
		if err != nil {
			continue
		}
		b.Write(raw)
		b.WriteByte('\n')
	}
	tmp := l.path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, l.path)
}
