# CRM 示例域名统一实施计划

> 执行方式：使用 `superpowers:executing-plans` 在当前会话逐项实施。

**目标：** CRM 服务域名统一为 `mirrors.example.com`。
**架构：** 在现有示例与部署文件中直接替换，不引入新的运行时配置。
**技术栈：** Go、Markdown、Caddy、Nginx。
**设计文档：** [域名统一设计](../specs/2026-09-29-mirror-example-domain-design.md)。

## 全局约束与审查重点

- 仅修改 CRM 地址，保留上游、参考链接、内部和测试主机。
- 协议、端口、路径、查询参数、凭据占位符保持原语义。
- Nginx 两个 server_name 与两个证书目录必须一致。
- Docker 登录/拉取、Containerd host/header 和代理示例全部覆盖。
- 在 `fix/mirror-example-domain` 分支实施；保留主目录已有修改，不推送。

## 任务 1：统一域名并验证

**修改文件：** `main.go`、`README.md`、`Caddy`、`nginx.conf`，
`docs/superpowers/specs/2026-09-28-docker-hub-mirror-design.md`，
`docs/superpowers/specs/2026-09-28-crm-basic-auth-design.md`。
**接口：** 只修改既有字符串，API 和配置结构不变。

- [x] 运行 `go test ./...` 确认基线；预期退出码 0。
- [x] 替换 CRM 域名及相应占位符，并用 `git diff` 逐项确认范围。
- [x] 运行 `go test ./...`；预期全部通过。
- [x] 用临时二进制和 Unix socket 启动匿名/认证实例，通过 HTTP GET `/`
  验证所有 CRM 示例使用目标域名，且原有上游和项目链接保留；预期全部通过。
- [x] 扫描旧域名及占位符；预期无遗漏。运行 `git diff --check`；预期退出码 0。
- [x] 独立只读审查后，本地提交改动及两份中文文档，不推送。

## 计划自查

范围只有一个可独立验收的字符串迁移任务；无需拆分模块或新增配置。
复用既有单元测试与临时进程验收，不新增仅复述字符串的永久测试。
并行子任务仅审计文件，所有写入由主 agent 完成。

## 验证记录

- 基线 `go test ./...` 通过（4.038 秒）；修改后再次通过（3.880 秒）。
- `go build -o /tmp/crm-domain-check .` 成功。
- 临时 Unix socket 真实进程：匿名和启用认证两种模式均通过 HTTP GET `/`
  检查首页 8 处 CRM 地址，以及原有 Docker 上游和 GitHub 项目链接。
- 全部受版本控制文本的旧 CRM 地址和占位符扫描通过；Nginx 的两个
  `server_name` 与两个证书目录均一致；`git diff --check` 通过。
- 文档/部署审计与代码/测试审计结论一致，均未发现其他应替换的 CRM 主机。
- 本机没有 Caddy/Nginx 可执行程序，未运行它们的配置加载检查；未部署 DNS
  或证书，也未运行与本次字符串修改无关的 Docker 拉取 E2E。
- 最终独立只读审查：无可操作缺陷；确认全部改动符合已确认范围。
