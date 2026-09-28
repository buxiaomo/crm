# 单一 listen 配置设计

## 问题与目标

当前配置要求 `listen` 为 TCP 地址，再通过 `socket_path` 增加第二个监听器。按用户最新要求，将两字段合并为 `listen`，每个进程仅监听一种入口。

## 配置契约

- `listen: "8888"`、`listen: ":8888"` 或 `listen: "127.0.0.1:8888"`：监听 TCP；保留 IPv6 地址支持。
- `listen: "/run/crm.sock"`：监听 Unix socket。路径必须是绝对路径，避免将错误的 TCP 地址解释为文件名。
- 空值、无效 TCP 地址、相对 socket 路径必须报错；没有默认 TCP 端口。
- 移除 `socket_path` 配置字段；旧 socket 部署必须把路径迁移到 `listen`。配置加载仍沿用现有 YAML/YML/JSON 规则，不新增未知字段全局校验。
- 保留 socket 目录/普通文件/符号链接保护，以及活动 socket 拒绝覆盖、失效 socket 清理逻辑。

## 最小实现与部署

`Config.Validate` 依据绝对路径区分 socket，否则验证 TCP 地址并将裸数字端口规范化为 `:端口`。启动同样依据绝对路径，复用 `listenUnix` 或标准库 `net.Listen` 选择一个监听器，由同一个 `http.Server.Serve` 服务和关闭。

保留超时、socket 权限和信号处理，绑定成功后才记录实际地址。删除重复 server、关闭逻辑及不可达的 `:8080` 默认值，不新增模式字段、工厂、依赖，不修改 HTTP API。

`config.yaml` 使用 `listen: "/run/crm.sock"`。README 给出 TCP 和 Unix 两套示例；Caddy/nginx 默认继续连接 socket，删除 nginx 的 TCP backup，并说明 TCP 前向代理需要切换 listen 和反向代理上游。

## 验证与兼容风险

单元测试覆盖裸端口、TCP 地址、IPv6、socket 路径、空值/非法地址/缺失目录、文件保护。进程 E2E 使用短临时目录、随机 TCP 端口和独立 socket，验证健康检查、唯一监听日志、非法配置退出、活动 socket 绑定失败及 SIGTERM 清理，无需 Docker 或外网。

旧配置中的 `socket_path` 不再生效；原双配置保留的 `listen: ":8888"` 会选择 TCP。选择 socket 时须把 listen 改为路径，不再开放 8888；需要前向代理端口的客户端应选 TCP 模式。中文设计与实施计划随修复提交，未经用户同意不推送。
