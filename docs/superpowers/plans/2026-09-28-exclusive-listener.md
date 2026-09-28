# 单一 listen 配置实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: 使用 superpowers:executing-plans 按任务执行，独立审查并行开展。

**Goal:** 将 listen/socket_path 合并为 listen，按端口或绝对路径选择 TCP 或 Unix socket。

**Architecture:** 配置校验将裸端口规范化为 TCP 地址，绝对路径选择 Unix。复用现有 listenUnix 和标准库，仅创建一个监听器和 HTTP server。

**Tech Stack:** Go 标准库、已有 YAML 依赖、Bash/curl 进程 E2E；不增加依赖。

**Spec:** `docs/superpowers/specs/2026-09-28-exclusive-listener-design.md`

## Global Constraints

- 仅保留 listen；支持裸端口、host:port、:port、IPv6 地址及 Unix 绝对路径。
- 不默认开启 TCP，不修改 HTTP API，保留 socket 文件保护和 SIGTERM 清理。
- 分支 fix/exclusive-listener，项目内 .worktrees/fix/exclusive-listener；仅本地提交。

## Review Focus

- 旧 socket 安全测试不能被格式错误短路：修改为 listen 路径并检查具体拒绝原因。
- socket 单配置不得启用隐含 TCP：真实进程健康检查及唯一监听日志。
- 绑定失败不得记录正在监听：E2E 使用活动 socket 触发失败且原进程仍健康。
- SIGTERM 后应退出并清理 socket：E2E 检查退出状态和文件不存在。
- 文档与默认配置应使用单字段：检查 nginx/Caddy 上游及旧配置迁移说明。

### Task 1: 配置、启动与部署说明同步

**Files:** 修改 main.go、main_test.go、config.yaml、README.md、Caddy、nginx.conf；新增 tests/e2e-listener.sh。

**Interfaces:** 保持 (*Config).Validate() error 和 listenUnix(string) (net.Listener, error)；删除 Config.SocketPath。

- [x] 增加 TestValidateListenerSelection：裸端口 8888 规范化为 :8888；TCP/IPv6/Unix 路径通过；空值、localhost、相对路径、缺失目录报错；修改既有 socket 安全测试以使用 listen 路径并保留保护断言。
- [x] 运行 go test ./... -run 'TestValidate|TestSocketValidation' -count=1，预期裸端口和 socket 路径失败，确认根因。
- [x] 增加 tests/e2e-listener.sh，真实二进制覆盖显式 TCP、裸端口 0、Unix /healthz、唯一日志、非法配置、socket 绑定失败与清理；先运行确认旧实现失败。
- [x] 修改校验与 main 为单监听器；更新示例配置、迁移说明、部署注释和 E2E 使用方法。
- [x] 运行定向测试、go test -race ./...、go vet ./...、bash tests/e2e-listener.sh、make build；预期全部成功。
- [x] 复核 diff、独立 agent 审查并提交代码、测试、中文设计与计划。

## 计划自审

用户后续明确要求合并字段，原互斥方案已经替换。仅一个任务，复用已有函数和标准库，无需新配置枚举、工厂或 Docker 拉取测试；五项审查重点均有验证。HTTP API 未改动。

## 验证记录

- 基线 go test ./... 通过。
- 新单元测试在旧实现中因裸端口和 socket 路径被拒绝而失败；修改后定向回归通过。
- 真实进程 E2E 在旧实现中因日志仍打印端口 0 而失败；修改后所有场景通过。
- go test -race ./... -count=1 通过；go vet ./...、make build、git diff --check 通过。
- 本机沙箱不允许写默认 Go 构建缓存，验证时使用 GOCACHE=/tmp/crm-listener-go-cache；未改变项目配置。
- 两个并行调研确认根因和旧 socket 测试的短路风险，部署说明中的双监听假设已同步修正。
- 独立最终审查：Critical/Important/Minor 均无；没有未解决风险或搁置项。
