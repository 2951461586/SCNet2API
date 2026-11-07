// Package envfile 在进程启动最早期加载 .env。
//
// Go 没有内建的 dotenv；本包只支持最简单的 KEY=VALUE 语法，但因为
// 它在 flag 默认值求值之前运行，所以写进 .env 的密钥对主进程真正生效。
package envfile

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// Load 读取 .env 并写入进程环境（已存在的变量不覆盖）。
//
// 查找顺序：SCNET2API_ENV_FILE 指定的路径 → 可执行文件同目录 → 当前目录。
func Load() string {
	candidates := []string{strings.TrimSpace(os.Getenv("SCNET2API_ENV_FILE"))}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), ".env"))
	}
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(wd, ".env"))
	}
	for _, path := range candidates {
		if path == "" {
			continue
		}
		if loadFile(path) {
			return path
		}
	}
	return ""
}

// loadFile 解析单个 .env；文件不存在时返回 false。
func loadFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		value = strings.TrimSpace(value)
		// 去掉包裹引号；引号内的 \n 不做转义展开（够用即可）。
		if len(value) >= 2 {
			if (value[0] == '"' && value[len(value)-1] == '"') ||
				(value[0] == '\'' && value[len(value)-1] == '\'') {
				value = value[1 : len(value)-1]
			}
		}
		if _, exists := os.LookupEnv(key); exists {
			continue
		}
		_ = os.Setenv(key, value)
	}
	return true
}
