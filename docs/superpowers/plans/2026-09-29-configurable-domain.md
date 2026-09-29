# CRM 首页域名配置实施计划

> 使用 `superpowers:executing-plans` 在本会话实施，先测试再实现。

**目标：** 修改 `domain` 配置并重启即可更新全部首页 CRM 地址。
**架构：** 复用配置读取、校验、handler 初始化和首页说明块；只增加一个配置字段。
**技术栈：** Go 标准库、现有 YAML 依赖、Bash E2E。
**设计：** [域名配置设计](../specs/2026-09-29-configurable-domain-design.md)。

## 全局约束与审查重点

- 缺省或空字符串使用 `mirrors.example.com`；已有配置兼容。
- 域名不带协议、端口或路径，遵守 ASCII DNS 主机名长度和字符规则；
  须包含点号或为 `localhost`，防止 Docker 将其解析为 Hub 命名空间。
- 请求 Host 不能控制首页示例；输出必须安全，真实上游和项目链接保留。
- 所有八处 CRM 地址同步变化，前向代理保留 `http://` 与 `:8888`。
- 配置修改后重启生效，不新增热加载；不碰主目录现有配置修改，不推送。

## 任务 1：配置驱动首页与完整验证

**文件：** `main.go`、`main_test.go`、`config.yaml`、`README.md`、
`tests/e2e-listener.sh`，以及本设计和计划。
**接口：** 新增 YAML/JSON 字段 `domain`；HTTP API 和其他配置结构保持不变。

- [x] 增加 `TestDomainConfigValidation`，覆盖有效主机、长度边界、空值和非法输入。
- [x] 增加 `TestIndexConfiguredDomain`，经真实配置加载验证八处首页地址、
  缺省兼容、认证模式与请求 Host 隔离；先运行并确认因功能缺失失败。
- [x] 扩展监听 E2E 的现有启动循环，依次使用缺省域名和两个不同域名，
  只构建一次，HTTP 请求检查当前配置；增加非法域名启动失败场景。
  在实现前运行并确认自定义域名断言失败。
- [x] 最小实现配置字段、校验、handler 值和首页格式化；更新示例配置与 README。
- [x] 运行 `go test ./...`、`go test -race ./...`、`go vet ./...`，预期全部通过。
- [x] 运行 `bash tests/e2e-listener.sh`，预期所有新旧场景通过；
  运行 `git diff --check`，预期无格式问题。
- [x] 独立只读审查变更及上游边界，修复有效问题后本地提交。

## 计划自查

单个功能没有可独立交付的模块边界，因此保留一个实施任务。
复用首页说明块与已有监听 E2E，不添加模板系统、文件监听或新配置文件。
代码链路与测试方案由两个只读子任务并行核对，主 agent 统一实现与验收。

## 验证记录

- 基线 `go test ./...` 通过（4.076 秒）。默认 Go 缓存目录受到沙箱限制，
  本次命令统一使用临时 `GOCACHE=/tmp/crm-configurable-domain-go-cache`，无需改项目配置。
- 单元测试 RED：旧实现接受非法域名；YAML/YML/JSON 自定义域名均未生成预期首页。
- E2E RED：同一二进制重启至 `bare_port` 阶段后，首页仍缺少配置的自定义域名。
- 实现后针对性单元测试通过；全量 `go test ./...` 通过（3.995 秒），
  `go test -race ./...` 通过（5.182 秒），`go vet ./...` 通过。
- `bash tests/e2e-listener.sh` 通过：缺省及两次不同域名、请求 Host 隔离、
  非法域名启动拒绝，以及原有监听与退出场景全部通过；仅构建一次。
- `bash -n tests/e2e-listener.sh`、`git diff --check` 通过。
- 两个只读调研结论一致：复用现有加载链路、说明块和监听 E2E 即可，未新增依赖。
- 独立审查发现普通单标签主机与 Docker 命名空间存在歧义，已根据实际解析规则
  收紧为含点号域名或 `localhost`。新增 `crm` / `CRM` 用例先确认失败再修复，
  保留 `LOCALHOST` 大小写兼容；无其他可操作缺陷。
- 边界修复后最终验证：全量测试通过（3.898 秒），race 通过（5.390 秒），
  vet、监听及域名 E2E、差异格式检查全部通过；未留下未解决审查项。
- 在 `feature/configurable-domain` 本地提交代码、测试、示例配置和两份中文文档；
  沿用已有 worktree，未修改主目录的用户配置，未推送远程。
