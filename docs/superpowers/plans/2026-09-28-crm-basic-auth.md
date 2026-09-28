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
