# SCNet2API

把本机 **SCNet（超算互联网）客户端「计算服务」** 的上游模型服务，逆向复刻成一个
**OpenAI / Anthropic 双协议兼容的 Go 网关**。

复用桌面端已登录的会话（`accessToken`）自动换取模型 API Key，无需另申请密钥；
纯 Go 标准库实现，零外部依赖。

| 能力 | 说明 |
| --- | --- |
| 双协议 | OpenAI `/v1/chat/completions`、`/v1/responses`；Anthropic `/v1/messages` |
| 号池治理 | 分组轮询、失败换号、余额感知、并发上限、会话保活 |
| 登录方式 | desktopToken / 账号密码（自动续期）/ 手机号验证码 |
| 凭据自动化 | 任意登录态 → 平台会话 → 模型 API Key → MCP 搜索 Key，全链路自动 |
| 模型治理 | 上游目录动态同步、别名、兜底模型、默认模型 |
| 原生扩展 | 联网搜索（bocha）、余额 / 用量 / 团队账号视图 |
| 控制台 | 单页内嵌 UI：总览 / 账号 / 密钥 / 模型 / 日志 / 设置 |
| 安全 | 网关密钥、管理口令、同源写保护、状态文件 AES-256-GCM 可选加密 |

```text
┌──────────────┐  /v1/chat/completions   ┌───────────────┐   Authorization: Bearer sk-…   ┌──────────────────────────────┐
│ OpenAI SDK   │  /v1/responses          │  SCNet2API    │   ───────────────────────────▶ │ https://api.scnet.cn/api/llm │
│ Claude Code  │  /v1/messages           │   （本网关）   │   ◀─────────────────────────── │ /v1/chat/completions         │
│ pi / Cline   │  /v1/models             │               │        SSE / JSON             │ /responses / anthropic       │
└──────────────┘                         └───────┬───────┘                                └──────────────────────────────┘
                                                 │ 自动读取 / 自动换取
                                                 ▼
                    %APPDATA%/scnet-client/config.json
                    {"accessToken":"eyJ…","userInfo":{"id":"…","userName":"…"}}
```

---

## 一、逆向结论

SCNet 客户端是 **Electron + 本地 agent** 架构（应用版本 4.1.0），真正干活的是
打包在 `resources/app.asar` 里的 agent runtime。模型能力分成两个面：

### 1.1 平台面（会话鉴权）

请求头：`Cookie: Token=<uuid>; jsessionid=…` + `token: <X-Jwt-Access-Token>`。

| 方法 | 路径（基地址 `https://www.scnet.cn`） | 说明 |
| --- | --- | --- |
| POST | `/ac/api/auth/loginDesktopClientByToken.action` | `desktopToken` 换会话（表单字段 `desktopToken`） |
| POST | `/ac/api/auth/loginDesktopClient.action` | 账号密码登录（密码 RSA PKCS#1 v1.5 加密后 base64） |
| POST | `/ac/api/auth/sendDesktopClientPhoneCode.action` | 发送短信验证码（表单字段 `phoneNum`，返回会话 Cookie） |
| POST | `/ac/api/auth/loginDesktopClientByPhoneCode.action` | 手机号 + 验证码登录（`messageCode`，带上一步 Cookie） |
| GET | `/acx/user/users/current-user-info?includeToken=true&refresh=true` | 用户资料 |
| GET | `/acx/user/users/cluster-user-detail` | 团队账号 / 余额（`accountDetail.balance`） |
| GET | `/acx/llm/account/config/status?accountId=` | 模型服务开关 / 欠费 / 停用标记 |
| POST | `/acx/llm/account/config/authorize?accountId=` | 自动开通模型服务 |
| GET | `/acx/llm/api/console/model` | 模型目录（含协议、价格、上下文） |
| POST | `/acx/llm/api-key/createActivityApiKey` | 活动 Key，直接返回 `apiKey/baseUrl/anthropicBaseUrl` |
| POST | `/acx/llm/api-key/query` | Key 列表（`keyStatus=100` 为正常） |
| POST | `/acx/llm/api-key/detail?id=` | Key 明文 |
| POST | `/acx/llm/api-key/create` | 标准 Key 创建（`serviceTypes=["model"]`） |
| POST | `/acx/llm/api-key/mcp/create` | 联网搜索用 MCP Key（`serviceTypes=["mcp"]`） |

### 1.2 模型面（API Key 鉴权）

基地址由平台下发（默认 `https://api.scnet.cn/api/llm/v1`）：

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/v1/models` | 模型网关侧的模型 ID 列表 |
| POST | `/v1/chat/completions` | OpenAI Chat Completions（SSE / 非流式） |
| POST | `/v1/responses` | OpenAI Responses |
| POST | `https://api.scnet.cn/api/llm/anthropic/v1/messages` | Anthropic Messages |
| POST | `https://api.scnet.cn/api/llm/web-search` | 联网搜索（bocha），需 MCP Key |

关键事实：

- **鉴权**：模型面统一 `Authorization: Bearer sk-…`；Anthropic 同时接受 `x-api-key`。
- **错误**：余额不足为 `402 {"error":{"message":"Insufficient Balance"}}`；
  `priceLabel=free` 的模型（目前 `SCNet-Max`）在欠费时仍可调用。
- **模型目录**：`maxToken` 单位是 KiB（桌面端按 ×1024 换算上下文窗口），
  `protocols` 声明该模型支持 `OPENAI_CHAT` / `OPENAI_RESPONSES` / `ANTHROPIC`。
- **会话寿命**：`X-Jwt-Access-Token` 有效期 30 分钟，本网关在 25 分钟时主动续期。

---

## 二、快速开始

```bash
# 1) 编译
make build          # 产物 bin/scnet2api.exe；也可 go build -o scnet2api.exe .

# 2) 直接启动（自动导入桌面端登录态 + 取 Key + 拉模型目录）
./bin/scnet2api.exe

# 3) 打开控制台
#    http://127.0.0.1:10088/

# 4) 签发网关密钥（控制台「网关密钥」页），然后调用
curl http://127.0.0.1:10088/v1/chat/completions \
  -H "Authorization: Bearer sk-scnet-..." \
  -H "Content-Type: application/json" \
  -d '{"model":"SCNet-Max","messages":[{"role":"user","content":"hi"}]}'
```

Claude Code / Anthropic SDK：

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:10088
export ANTHROPIC_API_KEY=sk-scnet-...
export ANTHROPIC_MODEL=SCNet-Max
```

OpenAI SDK / Cline / pi：

```bash
export OPENAI_BASE_URL=http://127.0.0.1:10088/v1
export OPENAI_API_KEY=sk-scnet-...
```

> 未签发任何网关密钥时，只有本机回环请求被放行（便于自举）；非回环请求返回
> `503 setup_required`。

### 登录方式

账号既可以用桌面端登录态，也可以直接用账号密码或手机号验证码添加：

| 方式 | 入口 | 续期 |
| --- | --- | --- |
| `desktopToken` | 自动读取 `config.json`；或在控制台粘贴 / `SCNET_DESKTOP_TOKEN` | 每 20 分钟自动重新登录（token 过期后回落到账号密码，若已配置） |
| 账号密码 | 控制台「② 账号密码登录」或 `POST /admin/api/accounts`（`username` + `password`） | 会话过期后自动用密码重登；登录响应带长效令牌时自动升级为 desktopToken |
| 手机号验证码 | 控制台「③ 手机号验证码登录」：发送 → 填码（两步） | 只保存会话；上游会话失效后需重新收码（已签发的模型 Key 不受影响） |

实现说明：

- 密码用客户端内置的 **512-bit RSA 公钥**（从 `app.asar` 提取）做 PKCS#1 v1.5 加密后 base64，
  与桌面端 `publicEncrypt` 一致。Go 1.24 的 `crypto/rsa` 会拒绝 512-bit 密钥，
  因此本网关按 RFC 8017 手工实现了一次模幂（只复刻报文格式，不承担机密性）。
- 密码是否落盘取决于状态文件加密：未设置 `SCNET2API_MASTER_KEY` 时会明文保存，
  启动日志与控制台都会告警；建议首次部署就开启加密后再添加密码账号。
- 手机号验证码的中间 Cookie 只放在内存（5 分钟 TTL），不落盘。

### 诊断工具

```bash
go run ./cmd/probe -usage                 # 登录 + 余额 + 模型目录
go run ./cmd/probe -prompt "hello"        # 真实调用一次
go run ./cmd/probe -prompt "hi" -stream   # 流式调用
go run ./cmd/probe -key sk-... -prompt hi # 直接验证模型 Key
go run ./cmd/probe -search "超算互联网"    # 联网搜索
```

### 加密状态文件

状态文件里是上游会话与 API Key。首次部署就建议开启加密：

```bash
printf 'SCNET2API_MASTER_KEY=%s\n' "$(openssl rand -hex 32)" >> .env
./bin/scnet2api.exe -seal -yes   # 把存量明文封存为密文后退出
./bin/scnet2api.exe              # 之后每次保存都自动加密
```

`-seal` 会打印密钥指纹（sha256 前 8 字节）便于核对。**主密钥必须与备份一起保管，
丢失后号池不可恢复。**

---

## 三、接口清单

### OpenAI 兼容

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/v1/models` | 模型目录（含 `scnet` 元信息） |
| POST | `/v1/chat/completions` | 流式 / 非流式；`reasoning_content` 归一化 |
| POST | `/v1/responses` | 仅支持 `OPENAI_RESPONSES` 的模型 |

### Anthropic 兼容

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/v1/messages` | 流式 / 非流式，`tool_use` / `thinking` / 图片由上游原生支持 |
| POST | `/v1/messages/count_tokens` | 本地估算（上游不提供） |

### SCNet 原生扩展

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/v1/scnet/web_search` | 上游联网搜索（`{query,count,freshness,summary}`） |
| GET | `/v1/scnet/balance` | 当前账号余额 / 欠费 / 模型服务状态 |
| GET | `/v1/scnet/usage` | 用户 + 余额 + 打码凭据 + 会话摘要 |

别名：`/v1/web_search`、`/v1/balance`、`/v1/usage`。

### 管理接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/admin/api/state` | 账号 / 密钥 / 设置 / 模型 / 统计 |
| GET | `/admin/api/overview` | 聚合指标 |
| POST | `/admin/api/accounts` | `add` / `import` / `update` / `enable` / `disable` / `refresh` / `probe` / `delete` |
| POST | `/admin/api/accounts/probe` | 批量探测（`id` / `group` / `stale_only` / `limit`） |
| POST | `/admin/api/import` | 从桌面端目录导入登录态 |
| POST | `/admin/api/login/phone/send` | 发送手机号验证码（`{phone}`） |
| POST | `/admin/api/login/phone/verify` | 验证码登录并添加账号（`{challenge,code,name,group}`） |
| GET/POST | `/admin/api/keys` | 列表 / 签发 / 启停 / 删除 |
| GET | `/admin/api/logs` | 最近日志 |
| GET/POST | `/admin/api/stats` | 统计 / 重置 |
| GET/POST | `/admin/api/settings` | 设置 |
| GET/POST | `/admin/api/models` | 目录 / 刷新 / 默认模型 |
| POST | `/admin/api/search` | 控制台联调联网搜索 |

鉴权：`X-Admin-Password` 或 `Authorization: Bearer <管理密码>`；写操作额外做同源校验。

---

## 四、命令行参数与环境变量

| 参数 | 环境变量 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `-host` | `SCNET2API_HOST` | `127.0.0.1` | 监听地址 |
| `-port` | `SCNET2API_PORT` | `10088` | 监听端口 |
| `-data` | `SCNET2API_DATA_PATH` | 用户配置目录 | 状态文件 |
| `-client-dir` | `SCNET2API_CLIENT_DIR` | 自动探测 | 桌面端数据目录 |
| `-admin-password` | `SCNET2API_ADMIN_PASSWORD` | 空 | 管理密码 |
| `-allow-insecure` | `SCNET2API_ALLOW_INSECURE` | `false` | 允许非回环监听且无鉴权 |
| `-import` | — | — | 仅导入 + 取 Key 后退出 |
| `-no-import` | — | — | 启动时不自动导入 |
| `-seal` / `-yes` | — | — | 将状态文件封存为密文 |
| `-version` | — | — | 打印版本 |

其他环境变量：

| 变量 | 说明 |
| --- | --- |
| `SCNET_DESKTOP_TOKEN` | 直接添加一个账号（desktopToken） |
| `SCNET_USERNAME` / `SCNET_PASSWORD` | 用账号密码添加一个账号（启动时登录并取 Key） |
| `SCNET2API_API_KEY` | 直接导入一个网关密钥 |
| `SCNET2API_MASTER_KEY` | 状态文件加密主密钥（64 位 hex / base64 32 字节） |
| `SCNET2API_WEB_ORIGIN` / `SCNET2API_API_ORIGIN` | 覆盖平台 / 模型网关地址（自建测试） |
| `SCNET2API_ADMIN_PASSWORD` | 管理密码 |
| `PROXY_POOL` | 预留：账号级 `proxy` 字段优先于环境代理 |

---

## 五、架构

```text
main.go                    启动、自动导入、会话保活、优雅退出
internal/
  scnet/                   上游协议层（无状态，可并发复用）
    types.go               模型 / 凭据 / 会话 / 账号 / 余额
    client.go              HTTP 传输、desktopToken 登录、acx 请求
    keys.go                createActivityApiKey → 标准 Key 回落、MCP Key
    catalog.go             模型目录（LLM 过滤、上下文换算）
    inference.go           chat / responses / anthropic 调用
    search.go              联网搜索（嵌套响应归一化）
    probe.go               用户 / 团队 / 余额 / 模型服务探测
    sse.go                 SSE 帧解析 + 增量提取
    errors.go              HTTPError 分类（鉴权 / 余额 / 可重试）
  store/                   持久化（账号 / 密钥 / 设置 / 日志 / 统计 / 加密）
  pool/                    选号策略（分组 + 失败度 + 余额感知 + 轮询游标）
  registry/                模型别名与回落
  server/                  HTTP 层
    common.go              账号准备、会话 / 凭据刷新、失败换号、日志统计
    chat.go / responses.go / anthropic.go   三协议处理器
    extensions.go          联网搜索 / 余额 / 用量
    admin.go               控制台 API + 桌面端导入
    web/index.html         内嵌单页控制台
  envfile/                 .env 加载（先于 flag 默认值求值）
cmd/probe/                 离线诊断 CLI
```

### 请求生命周期

1. 校验网关密钥 → 解析模型名（别名 / 兜底）→ 注入 SCNet 模型 ID；
2. 选号：按密钥分组过滤，优先失败次数少、余额充足的账号；
3. 账号准备：会话过期则用 desktopToken 重新登录；模型 Key 缺失则自动创建；
4. 调用上游；`401/403` 强制重建 Key 后重试一次；`402` 标记欠费并换号；
5. 流式透传 / 非流式归一化（模型名、`reasoning_content`）；
6. 记录日志与 token 统计（不落对话内容）。

### 为什么这样分层

- `scnet` 不持有状态：同一套协议既能被网关、CLI、测试复用；
- `store` 不实现调度：选号规则改动不需要碰持久化；
- `server` 只做编排：三种协议的差异集中在各自 handler，公共重试逻辑只有一份。

---

## 六、模型说明

目录完全由上游下发（当前 32 个 LLM，快照见控制台）。部分模型：

| ID | 上下文 | 协议 | 价格 |
| --- | ---: | --- | --- |
| `SCNet-Max` | 1,048,576 | Chat / Responses / Anthropic | 免费 |
| `DeepSeek-V4.1-Flash` | 1,048,576 | Chat / Responses / Anthropic | 计费 |
| `Kimi-K3` | 1,024,000 | Chat / Responses / Anthropic | 计费 |
| `GLM-5.3` | 1,048,576 | Chat / Responses / Anthropic | 计费 |
| `Qwen3.8-Max` | 1,048,576 | Chat / Responses / Anthropic | 计费 |
| `Spark-X2.5` | 262,144 | Chat / Anthropic | 计费 |
| `Qwen3-235B-A22B` | 32,768 | Chat | 特殊 |

内置别名（可在控制台覆盖）：`gpt-4o` / `gpt-4` / `gpt-3.5-turbo` /
`claude-sonnet-4` / `deepseek-chat` / `qwen` … → `SCNet-Max`。
`scnet/`、`openai/`、`anthropic/` 前缀会被自动剥离；无法识别的模型名回落到
「兜底模型」→「默认模型」。

**欠费账号只建议使用免费模型**：其余模型会稳定返回 `402 Insufficient Balance`，
网关会把它标记为欠费并优先调度其他账号。

---

## 七、测试

```bash
go test ./...        # 单元测试
go test -race ./...  # 竞态检测
```

覆盖：模型别名回落、号池轮询 / 分组 / 余额、SSE 解析、用量提取、错误分类、
持久化 / 加密 / 日志裁剪、网关鉴权 / CORS / 管理面 / 桌面端导入。

---

## 八、已知边界

- 只支持上游声明的协议：模型不支持 `OPENAI_RESPONSES` 时 `/v1/responses`
  返回 400，不做 chat 翻译；Anthropic 协议同理。
- 上游不提供 `count_tokens`，本地按 `字符数 / 4` 估算。
- 手机号验证码登录需要人工收码（控制台两步）；上游会话失效后需重新验证，
  但已创建的模型 API Key 仍可继续推理。
- 密码登录依赖客户端内置的 512-bit RSA 公钥；上游若轮换公钥需要同步更新
  `internal/scnet/login.go` 中的 `rsaPublicKeyBase64`。
- 联网搜索返回的是上游 bocha 结果，摘要质量与时效由上游决定。
