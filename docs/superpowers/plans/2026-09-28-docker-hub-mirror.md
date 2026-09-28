# Docker Hub 镜像加速器实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

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

- [x] 编写 `TestMirrorPull`：真实本地 HTTP 入口和 TLS auth/registry/CDN 服务；请求 nginx 的 HEAD/GET，验证 token pull scope、ns 被移除、上游敏感头剥离、字节/digest/Range。
- [x] 编写 `TestMirrorRejectsRequests` 与错误/跳转测试，覆盖审查重点中的边界。
- [x] 运行 `go test -run TestMirror -v .`；预期新增入口测试因当前 400 失败。
- [x] 实现只读路由、匿名 token、ReverseProxy 流式回传与受限重定向；Makefile 使用 `go build -o crm .`。
- [x] 运行 `go test ./...`；预期新旧测试全部通过。
- [x] 提交此任务。

### Task 2: 配置文档与真实验收

**文件：** 修改 README、首页、Caddy/nginx 说明；新增 `tests/e2e-mirror.sh`（隔离真实 Docker E2E）；更新计划验证记录。

**接口：** 使用 Task 1 的 `/v2/` 和公开镜像拉取行为；E2E 通过环境/参数指定独立 CRM 地址及 DinD 镜像。

- [x] 将首选文档改回 registry-mirrors，说明公开 Docker Hub、无缓存及旧代理兼容范围。
- [x] 编写独立 DinD E2E：黑洞出口、坏 mirror 阴性对照、有效 CRM 拉取 nginx:alpine，并只清理本次创建的容器。
- [x] 运行 `go test -race ./...`、`go vet ./...`、`make build`，预期通过。
- [x] 运行本地与真实 E2E，记录环境、结果及限制。
- [x] 子 agent 只读审查完整 diff，复核关键结论、修复阻断问题并验证。
- [x] 提交文档、E2E 和最终验证记录，不推送、不修改线上部署。

## 计划自查

两项任务共用 serveMirror 接口，无并行写入；主 agent 实现，子 agent 并行做协议调研、测试设计与最终只读审查。使用标准库而非额外 Registry 服务；不增加配置开关、缓存、管理后台或通用下载端点，避免过度设计。

## 验证记录

- 基线：`go test ./...` 通过，3.005s。
- RED：新增 mirror 测试确认原实现返回 400；GREEN：新旧测试全部通过。
- 最终代码检查：`go test -race ./...` 通过（4.425s），`go vet ./...` 与 `make build` 通过；脚本 `/bin/bash -n` 通过。
- 本地网络 E2E：固定 auth/registry/CDN 域名映射到 TLS 测试服务，HEAD/GET、index/manifest/config/layer、摘要、Range、超时取消、错误和恶意跳转均通过。
- 真实 Hub：nginx:alpine 的 index、arm64 manifest、config 和镜像层经本地 CRM 获取并通过 SHA256 检查。
- 真实 Docker E2E：隔离 Docker 29.8.1 / linux arm64；坏 mirror 与黑洞出口阴性对照通过，然后全新 daemon 经 CRM 完整拉取 nginx:latest 成功，digest 为 `sha256:abe47724e466aeab9a345d8e46a221c2fa8953c7848bb4a3bd9976a7199f8cf2`。
- E2E 证据：`/var/folders/j0/pgc0_9fn1259w1jn0dg8s9900000gn/T/crm-mirror-e2e.An2Wyx/`，含 negative/positive daemon、pull 和 inspect 日志。
- 环境问题：宿主 Docker 直接下载 DinD 工具镜像返回 502；用已有 Skopeo 经本地 CRM 下载 Linux arm64 镜像并 docker load 后完成验收，未更改宿主 daemon 配置。
- 测试诊断：Docker 29 返回首个 mirror 错误给 CLI，fallback 失败只写 daemon 日志；阴性断言按实际产物改查 daemon 日志中同一行的 Hub 域名、proxyconnect 和黑洞地址，未放宽标准。
- 协议/测试方案分别经子 agent 调研，最终独立只读代码审查通过，无重要遗留问题。
- 设计裁定：CDN 使用独立固定域名名单，不复用前向代理的其他 registry 白名单；代价是上游新增 CDN 时需根据证据更新。
- 未验证边界：未部署线上 Caddy/nginx HTTPS；未测私仓及 foreign layer（不在支持范围）。测试容器和网络由脚本清理，宿主 Docker 原配置未修改。
