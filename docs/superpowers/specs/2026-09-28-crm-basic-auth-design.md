# CRM 本地 Basic 认证设计

## 目标与现状

客户端可使用 `https://用户名:密码@CRM/v2/...` 或 HTTP Basic 请求头；只有配置中的用户能够使用 CRM 的镜像拉取和代理能力，凭据不转发给上游；说明页和监控读接口允许匿名访问。URL userinfo 由客户端转换为请求头，CRM 不解析 URL 路径中的密码。当前 main 的 mirror 已隔离客户端凭据，但全部入口均缺少访问认证。另一个未合并的 `feature/crm-auth` 使用路径密钥，不混入此次账号密码方案。

## 配置与行为

- 新增可选 `auth.users` 映射：用户名到密码；省略 `auth`（或 null）保持旧行为。显式 `auth: {}` 或空 users、空用户名/密码、用户名含冒号、账号密码含控制字符均拒绝启动，错误不包含凭据。
- 配置文件仅对服务账号可读（建议 0600）；修改账号后重启。示例只使用占位密码，不设置 admin/admin 默认凭据。
- `ProxyHandler.ServeHTTP` 在并发限流和路由之前认证，保护 mirror、普通代理及 CONNECT。仅普通 origin-form 的 GET /、GET /healthz、GET /metrics 精确豁免；HEAD/POST、编码变体、其他路径及 absolute-form/CONNECT 不豁免。
- 首页展示使用说明及默认仓库和配置 allowed_hosts 的实际白名单（去重、HTML 转义），不展示账号密码。metrics/healthz 公开聚合统计与健康状态（含请求量、流量、错误、连接和运行时间），用户已知悉此信息可见性；仍保留并发及请求限制。
- 服务端本地账号配置属于部署运维说明，仅保留在 README；首页提供客户端接入说明。README 和首页的 Containerd 认证示例均并入各自 Containerd 章节，不设独立认证章节。
- 除上述公开读接口，普通服务请求用 Authorization，失败返回 401 和 `WWW-Authenticate: Basic realm="CRM", charset="UTF-8"`；absolute-form 代理及 CONNECT 用 Proxy-Authorization，失败返回 407 和同格式 Proxy-Authenticate。缺少、重复、畸形、错误凭据均拒绝，不访问上游。
- 正常 401/407 认证挑战不计入服务故障错误率，避免健康检查误报。
- 使用 Go 标准库 BasicAuth 解析和 SHA-256 定长摘要的 constant-time 比较。无账号数据库、会话、JWT、token 缓存和新依赖。
- 服务请求认证成功后移除 Authorization、Proxy-Authorization；代理请求移除 Proxy-Authorization，保留真正的上游 Authorization。CONNECT 在拨号前认证，MITM 继承隧道认证，并丢弃解密请求中的 Proxy-Authorization。
- mirror 沿用现有请求头白名单和匿名上游 Bearer 流程；本地密码不进入 token、registry 或 CDN。日志隐藏 URL userinfo 与认证头，不记录配置密码。

## 客户端与边界

- curl 支持 URL userinfo，也可 `curl --user 用户名 URL` 交互输入密码，避免密码进入命令历史。
- Containerd 使用仅绑定 CRM host 的 `hosts.toml` header.Authorization；不对上游 host 配置该头。Basic 字符串只是 Base64，配置文件同样需要限制读取权限。
- 不声称 Docker Engine registry-mirrors 支持带账号密码的 URL；普通 curl 成功不能代替真实运行时验证。
- HTTPS 由现有 Nginx/Caddy 终止；CRM 的裸 HTTP 端口只用于可信内网或本机，外部必须经过 HTTPS。认证配置不会自动改变部署，也不让公开上游镜像变成私有仓库镜像。

## 验证

配置表测试覆盖 YAML/JSON、启用边界与无秘密错误；入口表测试覆盖公开路径的精确豁免及其余入口的 401/407、重复头；本地网络 E2E 验证首页展示白名单、公开接口不泄漏账号密码且不会授权后续拉取；真实本地 HTTP/TLS E2E 覆盖 URL userinfo、Hub/GHCR token/registry/CDN、HEAD/GET、摘要、成功后未认证请求仍被拒绝、前向代理与 CONNECT。日志回归确保 URL/认证头不泄漏。运行全量 Go 测试、race 与 vet；外部 Docker/CRI 拉取与线上部署分开报告。

## 取舍复核

只扩展现有配置和共用入口，不新增认证服务、用户管理界面或新依赖。共用入口保护前向代理，避免只修 mirror 留下绕过。保留原代理的上游认证语义，不把 CRM 密码用作上游凭据。

参考：[curl](https://curl.se/docs/manpage.html#-u)、[Containerd hosts](https://github.com/containerd/containerd/blob/main/docs/hosts.md#header-fields)。
