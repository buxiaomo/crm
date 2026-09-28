# Docker Hub 镜像加速器实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**目标：** 保留用户 registry-mirrors 配置并完整拉取公开 Linux Docker Hub 镜像。

**架构：** `/v2/` 分流到标准库 ReverseProxy；服务端匿名取 token，复用 Transport 并在服务器跟随受限 CDN 跳转。原代理逻辑保持兼容。

**技术栈：** Go 1.27.1、net/http、httptest、现有 YAML 依赖。

**设计：** `docs/superpowers/specs/2026-09-28-docker-hub-mirror-design.md`

## 全局约束

- 分支 `feature/docker-hub-mirror`；设计、计划和实现提交到本分支，不推送。
- 遵循 Google Go 风格；不增加依赖、磁盘缓存或私仓支持。
- 只读 Docker Hub，客户端敏感头不出站；固定认证与 registry 目标。
- 测试共享全局状态，不使用 t.Parallel；Docker E2E 串行隔离。

## 审查重点

1. namespace 重复/恶意 host、编码路径不得改变固定上游；用拒绝测试覆盖。
2. token 返回 429、坏 JSON、空 token；保持上游状态或返回 502。
3. CDN 恶意跳转、降级 HTTP、循环；拒绝且无凭证泄漏。
4. manifest 的摘要和镜像层 Range/HEAD；保持原始字节与头。
5. 新源文件被部署构建遗漏，以及客户端直连回退造成 E2E 假阳性；构建整包和黑洞出口验证。

### Task 1: 加速器请求链路

**文件：** 新增 `mirror.go`、`mirror_test.go`；修改 `main.go`、`Makefile`。

**接口：** `(*ProxyHandler).serveMirror(http.ResponseWriter, *http.Request)` 接收 `/v2/` 相对路径；私有 `mirrorTransport` 实现标准库 RoundTripper，取得匿名 token 并处理跳转。

- [ ] 编写 `TestMirrorPull`：真实本地 HTTP 入口和 TLS auth/registry/CDN 服务；请求 nginx 的 HEAD/GET，验证 token pull scope、ns 被移除、上游敏感头剥离、字节/digest/Range。
- [ ] 编写 `TestMirrorRejectsRequests` 与错误/跳转测试，覆盖审查重点中的边界。
- [ ] 运行 `go test -run TestMirror -v .`；预期新增入口测试因当前 400 失败。
- [ ] 实现只读路由、匿名 token、ReverseProxy 流式回传与受限重定向；Makefile 使用 `go build -o crm .`。
- [ ] 运行 `go test ./...`；预期新旧测试全部通过。
- [ ] 提交此任务。

### Task 2: 配置文档与真实验收

**文件：** 修改 README、首页、Caddy/nginx 说明；新增 `tests/e2e-mirror.sh`（隔离真实 Docker E2E）；更新计划验证记录。

**接口：** 使用 Task 1 的 `/v2/` 和公开镜像拉取行为；E2E 通过环境/参数指定独立 CRM 地址及 DinD 镜像。

- [ ] 将首选文档改回 registry-mirrors，说明公开 Docker Hub、无缓存及旧代理兼容范围。
- [ ] 编写独立 DinD E2E：黑洞出口、坏 mirror 阴性对照、有效 CRM 拉取 nginx:alpine，并只清理本次创建的容器。
- [ ] 运行 `go test -race ./...`、`go vet ./...`、`make build`，预期通过。
- [ ] 运行本地与真实 E2E，记录环境、结果及限制。
- [ ] 子 agent 只读审查完整 diff，复核关键结论、修复阻断问题并验证。
- [ ] 提交文档、E2E 和最终验证记录，不推送、不修改线上部署。

## 计划自查

两项任务共用 serveMirror 接口，无并行写入；主 agent 实现，子 agent 并行做协议调研、测试设计与最终只读审查。使用标准库而非额外 Registry 服务；不增加配置开关、缓存、管理后台或通用下载端点，避免过度设计。

## 验证记录

- 基线：待补充。
