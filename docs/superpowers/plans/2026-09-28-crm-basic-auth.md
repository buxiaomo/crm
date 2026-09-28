# CRM 本地 Basic 认证实施计划

> 执行方式：主 agent 按 executing-plans 实施，共用工作区的测试编写、只读调研及最终审查并行分派，文件范围互不重叠。

**目标：** CRM 校验本地账号密码，未认证请求不能使用任何入口，CRM 凭据不出站。

**架构：** 复用配置加载和 ProxyHandler；共用入口选择服务 Basic 或代理 Basic；mirror 保持上游匿名认证。

**技术栈：** Go 标准库、现有 yaml.v3、httptest。

**设计：** [CRM 本地 Basic 认证设计](../specs/2026-09-28-crm-basic-auth-design.md)。

## 全局约束

- 分支 `feature/crm-basic-auth`；工作目录 `.worktrees/feature/crm-basic-auth`，基于 main。用户明确要求项目内 worktree，使用指定位置，保留其他工作区。
- 中文设计和实施计划提交到分支；不推送、不合并、不部署。
- 显式空认证配置必须拒绝；旧配置省略 auth 仍可用。
- 服务 Basic 返回 401，代理 Basic 返回 407；所有入口无匿名豁免。
- 不引入依赖，保留原上游 Authorization 的含义。

## 重点审查

1. `/v2/` 探测、首页、healthz、metrics 不得绕过：入口表测试。
2. absolute HTTP、CONNECT 与 MITM 不能绕过或泄漏代理认证：代理和隧道 E2E。
3. 密码带冒号及 URL 特殊字符：URL userinfo 网络测试。
4. 重复/非法认证头、未知账号、成功请求后复用连接：拒绝表与网络序列。
5. URL userinfo、认证头和错误消息泄漏：日志与配置错误测试。

## 任务 1：认证入口、配置和测试

文件：新增 `auth.go`、`auth_test.go`，修改 `main.go`；复用 `main_test.go`、`mirror_test.go` 的测试设施。
接口：`AuthConfig{Users map[string]string}`、`Config.Auth *AuthConfig`、`ProxyHandler.auth *AuthConfig`；`(*AuthConfig).Validate() error`、`(*ProxyHandler).authenticate(http.ResponseWriter, *http.Request) bool`。

- [ ] 新增先失败的配置、入口与本地网络 E2E；通过 JSON 加载新配置使旧版本可编译且按行为失败。
- [ ] 运行 `go test -run 'Test.*Auth' -count=1 .`，记录因缺少认证导致的失败。
- [ ] 实现上述接口，认证在路由/限流之前；凭据只在所需入口使用并删除。
- [ ] 修正日志 URL userinfo 和请求认证头脱敏，MITM 出站删除 Proxy-Authorization。
- [ ] 运行目标测试、`go test -race ./...`、`go vet ./...`，分析而非掩盖失败。

## 任务 2：客户端文档与验收

文件：修改 `README.md`、`config.yaml`、`Makefile`（配置安装权限 0600）、`main.go` 首页说明；本计划记录验证结果。

- [ ] 文档说明启用/拒绝默认、curl 交互密码、Containerd 的 CRM host header、代理 407、健康检查认证和客户端兼容性边界。
- [ ] 只读独立审查实现和测试；主 agent 复核并修复实质问题。
- [ ] `gofmt`、`git diff --check`，复查全部需求与凭据隔离断言。
- [ ] 本地提交代码、测试和中文文档，不推送。

## 自查

一个配置块和一个认证函数足够，不增加 provider 抽象、会话或权限系统。真实 HTTP/TLS 测试直接覆盖凭据是否到达上游，无需为此创建第二套 Docker 环境。测试单独文件避免与主实现发生并行写冲突。

## 执行记录

待填写实际命令和结果。
