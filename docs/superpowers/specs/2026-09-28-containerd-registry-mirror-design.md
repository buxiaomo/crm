# Containerd 多仓库 mirror 修复设计

## 问题与证据

Containerd 将原始仓库放在 `ns` 查询参数中。CRM 当前在 `serveMirror` 中只接受 Docker Hub，并固定访问 Hub registry、token 和 CDN；`allowed_hosts` 只作用于前向代理。日志中的 GHCR/GCR 请求在约 100 微秒内返回 400，与本地拒绝路径一致。首页却列出了多个仓库的旧式 mirror 配置，能力说明互相矛盾。

## 目标与范围

用户现有 `certs.d/docker.io`、`ghcr.io`、`gcr.io` 配置继续使用同一个 CRM 地址。支持白名单内标准 Registry V2 公开镜像的 GET/HEAD manifest/blob 拉取；无 `ns` 时保持 Docker Hub。镜像名称、标签有效性及公开权限由上游决定，不将所有拉取错误归因于本次 400。

不增加依赖、磁盘缓存、私仓凭证、路径前缀路由或通用仓库适配器。Docker Engine 的 registry-mirrors 仍只用于 Docker Hub。

## 最小实现

- 在 `mirror.go` 统一解析单个非空 `ns`，只接受主机名及可选 `:443`；禁止 URL、userinfo、路径、IP 字面量与非标准端口。`docker.io` 规范化为 `registry-1.docker.io`，其他主机必须命中现有白名单。非法或不允许 namespace 返回 400，出站前移除 `ns`，保留其他查询和资源路径。
- 保留 Hub 固定匿名 token 流程及固定 CDN 范围，避免扩大原有 Hub 下载权限。
- 其他仓库先匿名请求；仅收到来自原始 registry 的 401 Bearer 挑战时，校验 HTTPS realm（默认/443、无 userinfo、白名单主机），匿名取 token 并对原始请求重试一次。scope 固定为实际 `repository:<name>:pull`，不接受上游扩大权限。token 请求禁止跳转；支持 `token`/`access_token`，限制响应解析大小。
- 新仓库下载跳转限 HTTPS 和白名单主机，最多 10 跳。GHCR 的公开下载域名 `pkg-containers.githubusercontent.com` 单独允许用于 GHCR 下载，不将它默认开放为 namespace。跨主机永不发送 registry token；后续跳回也不恢复 token。
- 客户端 Authorization、Cookie、代理凭证不出站；不修改 manifest 字节。保留摘要、Range、条件请求、上游错误状态及超时取消；响应不向客户端暴露上游认证或重定向。
- README 与首页同步说明多仓库配置、白名单及 token/CDN 可能需要额外放行的边界；删除“配置支持但实现不支持”的矛盾描述。

## 验证

复用现有本地 HTTP/TLS 测试服务，覆盖 GHCR/GCR HEAD/GET、manifest/config/layer 全链路、401→token→重试、公开 GCR 无需 token、白名单自定义仓库、敏感头隔离、非法 ns/realm/跳转、错误与 Hub 回归。测试不并行改动全局配置。

增加隔离 Containerd + crictl E2E：独立 Docker 容器与数据目录，使用黑洞出口代理禁止直连回退，先坏 mirror 阴性对照，再通过 CRM 拉取三个仓库的小型公开镜像。只允许一套 E2E 运行，不改宿主运行时配置。外部镜像不可用时保留错误并与本地协议验收分开报告。

## 成本与边界

每个非 Hub 资源至多一次匿名试探、一次取 token 和一次重试；只有实际性能证据才增加有界缓存。`allowed_hosts` 同时决定非 Hub mirror 出站范围，运营者应使用精确主机或带边界的正则；新 CDN 需要按实际错误放行。匿名限额、私仓和 foreign layer 外部 URL 不在此次保证范围。

依据：[Containerd hosts 配置](https://github.com/containerd/containerd/blob/main/docs/hosts.md)、[Registry token 认证](https://distribution.github.io/distribution/spec/auth/token/)。本地公开端点检查确认 GHCR 发出同域 Bearer realm，GCR distroless/static:nonroot 可匿名返回 200；线上 CRM 版本尚未核实。
