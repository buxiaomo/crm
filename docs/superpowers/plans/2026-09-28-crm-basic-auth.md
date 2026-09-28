# CRM 本地 Basic 认证实施计划

> 执行方式：主 agent 按 executing-plans 实施，共用工作区的测试编写、只读调研及最终审查并行分派，文件范围互不重叠。

**目标：** CRM 校验本地账号密码，未认证请求只能读取首页、健康检查和指标，不能使用镜像拉取或代理，CRM 凭据不出站。

**架构：** 复用配置加载和 ProxyHandler；共用入口选择服务 Basic 或代理 Basic；mirror 保持上游匿名认证。

**技术栈：** Go 标准库、现有 yaml.v3、httptest。

**设计：** [CRM 本地 Basic 认证设计](../specs/2026-09-28-crm-basic-auth-design.md)。

## 全局约束

- 分支 `feature/crm-basic-auth`；工作目录 `.worktrees/feature/crm-basic-auth`，基于 main。用户明确要求项目内 worktree，使用指定位置，保留其他工作区。
- 中文设计和实施计划提交到分支；不推送、不合并、不部署。
- 显式空认证配置必须拒绝；旧配置省略 auth 仍可用。
- 服务 Basic 返回 401，代理 Basic 返回 407；仅普通 GET /、GET /healthz、GET /metrics 匿名豁免。
- 不引入依赖，保留原上游 Authorization 的含义。

## 重点审查

1. `/v2/` 探测及非公开请求不得绕过；三个公开路径精确豁免：入口表与本地网络测试。
2. absolute HTTP、CONNECT 与 MITM 不能绕过或泄漏代理认证：代理和隧道 E2E。
3. 密码带冒号及 URL 特殊字符：URL userinfo 网络测试。
4. 重复/非法认证头、未知账号、成功请求后复用连接：拒绝表与网络序列。
5. URL userinfo、认证头和错误消息泄漏：日志与配置错误测试。

## 任务 1：认证入口、配置和测试

文件：新增 `auth.go`、`auth_test.go`，修改 `main.go`；复用 `main_test.go`、`mirror_test.go` 的测试设施。
接口：`AuthConfig{Users map[string]string}`、`Config.Auth *AuthConfig`、`ProxyHandler.auth *AuthConfig`；`(*AuthConfig).Validate() error`、`(*ProxyHandler).authenticate(http.ResponseWriter, *http.Request) bool`。

- [x] 新增先失败的配置、入口与本地网络 E2E；通过 JSON 加载新配置使旧版本可编译且按行为失败。
- [x] 运行 `go test -run 'Test.*Auth' -count=1 .`，记录因缺少认证导致的失败。
- [x] 实现上述接口，认证在路由/限流之前；凭据只在所需入口使用并删除。
- [x] 修正日志 URL userinfo 和请求认证头脱敏，MITM 出站删除 Proxy-Authorization。
- [x] 运行目标测试、`go test -race ./...`、`go vet ./...`，分析而非掩盖失败。

## 任务 2：客户端文档与验收

文件：修改 `README.md`、`config.yaml`、`Makefile`（配置安装权限 0600）、`main.go` 首页说明；本计划记录验证结果。

- [x] 文档说明启用/拒绝默认、curl 交互密码、Containerd 的 CRM host header、代理 407、健康检查认证和客户端兼容性边界。
- [x] 只读独立审查实现和测试；主 agent 复核并修复实质问题。
- [x] `gofmt`、`git diff --check`，复查全部需求与凭据隔离断言。
- [x] 本地提交代码、测试和中文文档，不推送。

## 自查

一个配置块和一个认证函数足够，不增加 provider 抽象、会话或权限系统。真实 HTTP/TLS 测试直接覆盖凭据是否到达上游，无需为此创建第二套 Docker 环境。测试单独文件避免与主实现发生并行写冲突。

## 执行记录

- 基线 `go test ./...` 通过（3.270s）。
- RED：原实现的最小 `/v2/` 门禁测试返回 200、预期 401；完整认证测试记录于 `/tmp/crm-basic-auth-agent-red.log`，覆盖未拒绝非法配置、未认证出站及 401/407 缺失。最小门禁用例随后并入覆盖全部入口的表测试，删除重复用例。
- 日志与 MITM 泄漏分别通过新增断言复现后修复；未改动失败断言以掩盖问题。
- GREEN：`go test -run 'Test.*Auth|TestMITMBodyLimit' -count=1 .` 通过（1.564s），包含本地真实 HTTP/TLS E2E。
- `GOCACHE=/tmp/crm-basic-auth-agent-gocache go test -race ./...` 通过（5.038s）；同一 GOCACHE 的 `go vet ./...` 通过。默认构建缓存写入受沙箱限制，改为临时缓存后验证通过，未改测试。
- 设计审查通过；补充了 YAML 类型错误可能回显密码的回归，配置解码错误只返回文件与格式，不回显输入值。
- 独立代码审查通过。唯一覆盖缺口已修复：现有 MITM 测试增加 anonymous/authenticated 两组，在 CONNECT 认证后使用独立上游 Bearer，并验证 Proxy-Authorization 不出站。
- 复核发现正常 401 挑战被计入全局错误率会令 healthz 误报 503；`TestAuthChallengePreservesHealth` 已 RED（503）→GREEN（200），仅移除认证拒绝时的故障计数。
- 最终 `go test -race -count=1 ./...`、`go vet ./...`、`go build -o /tmp/crm-basic-auth-verified .` 和 `git diff --check` 均通过；构建缓存使用上述临时路径。
- 只验证本地网络 E2E；未执行外部 Docker/CRI 拉取，未访问线上实例、部署、合并或推送。

## 任务 3：公开说明页与监控读接口（用户追加确认）

**范围：** 沿用本分支和 worktree；主 agent 实现，两个子 agent 分别只读核对认证边界及页面/文档；不改用户已有的 config.yaml 本地配置。
**文件：** auth.go、auth_test.go、main.go、main_test.go、README.md 和本设计/计划。
**接口：** isPublicRequest(*http.Request) bool 只匹配 GET、非绝对URL、空URL.Host以及 EscapedPath 精确等于 /、/healthz、/metrics。

- [x] 调整入口表，增加非 GET、绝对 URL 根路径/监控路径、编码变体、相似前缀拒绝用例；新增 TestAuthPublicEndpoints 的真实本地 HTTP E2E，验证三接口匿名可用且不展示配置，公开访问后 /v2/ 仍 401。
- [x] 运行目标测试观察 RED；白名单哨兵直接测试 serveIndex，避免仅因认证拒绝而掩盖信息泄漏。
- [x] 在共用认证入口精确豁免；本地页面/监控路由排除绝对URL代理请求，保留现有并发限制；删除白名单 HTML 及不再使用的 display 参数和字段。
- [x] 更新 README/首页/中文设计，明确公开统计信息和其余认证边界。
- [x] 目标测试、全量 race、vet、格式检查；独立只读审查后本地提交，不推送。

**过度设计自查：** 只增加一个供认证使用的路径判定函数，不引入新的配置开关、路由库或两版首页。测试复用既有 httptest 与代理设施。

### 本次验证记录

- 基线 `go test ./...` 通过（4.024s）。
- RED：公开接口返回 401、首页展示配置哨兵；授权代理请求上游根路径或监控路径时误返回 CRM 页面。日志分别为 `/tmp/crm-public-index-red.log` 和 `/tmp/crm-public-index-proxy-red.log`。
- GREEN：`go test -run 'TestAuthPublicEndpoints|TestAuthProtectsEveryEntry|TestAuthHTTPProxyCredentials' -count=1 .` 通过（0.640s），含真实本地 HTTP E2E；其他镜像和 MITM 本地 TLS E2E 由全量测试回归。
- 最终 `go test -race -count=1 ./...` 通过（5.356s）；`go vet ./...`、`go build -o /tmp/crm-public-endpoints-verified .`、`git diff --check` 通过。使用 `/tmp/crm-basic-auth-agent-gocache` 构建缓存。
- 用户已有的 config.yaml 内容哈希与修改前一致，不纳入本次提交。
- 两项独立只读审查均通过：认证边界及代理路由无旁路，页面、测试和文档范围一致。

## 任务 4：恢复首页实际仓库白名单（用户明确要求）

用户要求恢复白名单展示；任务 3 的隐藏列表决策被撤回，三个 GET 公开及其他入口认证保持不变。

- [x] 修改 TestAuthPublicEndpoints：默认/自定义白名单须显示，重复项去重，HTML 特殊字符转义；只把账号密码作为秘密断言，保留本地 HTTP E2E 和后续拉取拒绝断言。
- [x] 运行目标测试观察列表缺失的 RED；恢复 allowedDisplay 和列表渲染，直接复用构造函数已有 cfg，不重加冗余参数或更改认证流程。
- [x] 更新 README、首页和当前中文设计；全量测试、vet及独立只读复核后提交。

自查：仅恢复展示行为，不加开关、双版本首页、新依赖或权限逻辑；使用标准库 HTML 转义。保留用户未提交的 config.yaml。

验证记录：基线 `go test ./...` 通过（3.413s）；恢复展示测试先因列表缺失失败，随后 `go test -run TestAuthPublicEndpoints -count=1 .` 通过（0.663s，含直接渲染及本地 HTTP E2E）。全量 `go test -race -count=1 ./...`、`go vet ./...` 和 `git diff --check` 通过。独立只读审查通过，确认 auth.go 与路由未改；用户 config.yaml 内容哈希保持不变。本地提交，不推送。

## 任务 5：首页与 README 说明归位

用户明确要求：服务端本地账号配置只在 README 说明，首页不展示；Containerd 客户端认证并入各自现有 Containerd 章节。

- [x] 从 main.go 首页移除本地账号部署说明，保留实际仓库白名单；Containerd 请求头示例移入 Containerd 章节，Docker 兼容性提示移入 Docker 章节。
- [x] README 保留可选服务端认证配置，明确其部署用途；对应客户端说明归入各运行时章节，同步设计文档。
- [x] 运行现有全量 Go 测试（含本地 HTTP/TLS E2E），检查页面和文档的章节归属；两项只读审查分别检查文档与页面/认证边界。
- [x] 核对 config.yaml 内容哈希未变；提交上述改动和中文文档，不推送。

过度设计自查：只移动、精简说明文字，不调整认证逻辑、模板结构或依赖，也不为文案位置新增固定文本测试。复用现有首页、白名单和认证 E2E 回归。

验证记录：基线 `go test ./...` 通过（3.318s）；改后 `go test -count=1 ./...` 通过（3.456s，含本地 HTTP/TLS E2E）。章节归属检查、`gofmt -l main.go` 和 `git diff --check` 通过；两项独立只读审查均无阻塞问题。认证实现、路由及测试未改动，config.yaml 内容哈希未变且不纳入提交。

## 任务 6：首页展示实际认证状态

**目标与范围：** 延续现有认证分支和工作区，在首页简介后显示认证开关状态；主 agent 修改 main.go 和文档，测试子 agent 仅修改 auth_test.go，另一个子 agent 只读复核。保留用户未提交的 config.yaml，不推送。

**接口：** `(*ProxyHandler).serveIndex(http.ResponseWriter, *http.Request)` 直接使用已有 `p.auth != nil`，与实际认证入口一致；不增加配置、端点、模板系统或客户端探测。

- [x] 在 auth_test.go 增加 TestIndexAuthStatus，覆盖配置省略、null、启用；直接渲染及本地 HTTP E2E 均验证对应状态、匿名首页 200、无凭据和服务端配置泄漏；首页访问后 `/v2/` 仍遵守认证配置。
- [x] 运行目标测试确认旧页面缺少状态而失败，再在 main.go 输出两种状态及启用时的提示框。
- [x] README 与设计同步说明首页展示认证状态；运行目标测试、全量 race、vet 和格式检查，独立复核后本地提交。

过度设计自查：仅在现有页面加一个条件分支，状态直接来自加载后的处理器配置；复用既有测试设施，不创建额外认证状态接口或读取配置文件副本。单元与本地 HTTP E2E 共用一组配置场景，避免重复测试框架。

验证记录：基线 `go test -count=1 ./...` 通过（3.622s）。新增测试先因两种状态文案缺失而失败（`/tmp/crm-index-auth-status-agent-red.log`）；实现后目标测试通过（0.600s）。全量 `go test -race -count=1 ./...` 通过（5.295s），`go vet ./...`、格式和差异检查通过；只读审查无阻塞问题。用户 config.yaml 哈希与修改前一致，不纳入提交；本轮仅提交到现有功能分支，不合并或推送。

合并跟进：用户随后授权合并到 main。合并前发现工作区文案已调整为“已开启认证 / 未开启认证”，旧文案断言导致基线失败；保留页面调整，仅同步测试的预期文案与设计说明，认证逻辑和其余断言不变。复测通过后合并，并验证 main 的原有单监听行为；真实账号配置不纳入提交。
