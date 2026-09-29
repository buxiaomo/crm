# Docker Hub 镜像加速器设计

## 目标与范围

用户保留 `{"registry-mirrors":["https://mirrors.example.com"]}`，直接执行 `docker pull nginx`；客户端不需要 HTTP_PROXY/HTTPS_PROXY。本次支持 Docker Hub 公开镜像的只读拉取，不增加磁盘缓存、私仓凭证、多仓库路由或第三方依赖。现有前向代理保留兼容。

## 已确认的问题

`main.go` 的非绝对 URL 检查自首提交起存在，普通 `/v2/...` 请求因此返回 400。旧 README 的 registry-mirrors 示例与实现不一致。加速器必须处理完整拉取流程，只删除 400 检查不能完成认证及下载。

## 方案与取舍

采用 Go 标准库 `httputil.ReverseProxy`，在现有入口分流 `/v2/` 请求。另一方案是给客户端重写认证 realm、增加 `/token`，但公开镜像无需维护这套接口；引入 Distribution 缓存服务则增加部署与存储成本。选择服务端匿名认证，复用现有 Transport、并发控制及请求超时。

- GET/HEAD `/v2/` 返回 200，声明 `Docker-Distribution-Api-Version: registry/2.0`。
- GET/HEAD `/v2/<repository>/manifests/<reference>`、`/v2/<repository>/blobs/<digest>` 转发到固定 `https://registry-1.docker.io`；原样保留内容、摘要、类型、长度、Range 和条件请求语义。
- `ns` 缺省、`docker.io`、`registry-1.docker.io` 可接受，转发前移除；其他或重复 namespace 拒绝。拒绝写方法和非拉取 API。
- 每个资源请求由服务端到固定 `https://auth.docker.io/token` 取得匿名 `repository:<repository>:pull` 令牌；不缓存令牌。禁止将客户端 Authorization、Cookie、代理凭证转发到上游。
- CDN 重定向由服务端跟随并流式返回；最多 10 跳，只允许 HTTPS、默认/443 端口、无 userinfo、固定 Docker Hub/CDN 白名单域名（独立于前向代理 allowed_hosts）。跨域去掉 Authorization，拒绝未放行的跳转。
- 上游 401/403/404/429/5xx 保留状态，剥离 WWW-Authenticate，避免客户端因认证挑战绕过加速器；连接/令牌解析错误返回 502。
- 不修改 manifest 字节，因此外部 foreign-layer URL 不在此次下载保证内；验收以标准 Linux Docker Hub 镜像为准。

## 文件与部署

新增 `mirror.go`、`mirror_test.go`；在 `main.go` 接入与更新首页，修改 README、Caddy/nginx 说明。Makefile 改为构建整个 package，避免遗漏新 Go 文件。现有 Caddy HTTPS 到 Unix socket 的链路可以使用，客户端配置不变。

## 验证

单元及本地网络 E2E 用 TLS 测试服务映射 registry/auth/CDN 固定域名，验证 nginx 路径含 ns 的 HEAD、完整 manifest/index/config/layer 流程、摘要、Range、认证剥离、跳转约束、错误透传。已有 HTTP/CONNECT/MITM 测试须继续通过。

真实 E2E 使用隔离 Docker-in-Docker，独立容器/数据目录且不暴露 Docker API；仅配置 CRM mirror，并用不可用出口代理阻断 Docker Hub 直连。先证明坏 mirror 拉取失败，再证明 CRM 下完整拉取成功。不修改宿主 Docker daemon 配置。若环境无法运行，明确保留未验证限制。

## 成本与边界

无磁盘缓存不消耗镜像存储，但服务端承担认证及下载流量、上游匿名额度；每资源重新取令牌会增加一次往返。先验证正确性，只有实测表明令牌往返成为瓶颈才加有界过期缓存。公开服务的访问控制沿用现有入口部署策略。

## 依据与自查

- https://distribution.github.io/distribution/spec/auth/token/
- https://docs.docker.com/docker-hub/image-library/mirror/
- https://github.com/opencontainers/distribution-spec/blob/main/spec.md

自查：不引入通用仓库适配器、任意 URL 下载接口、持久化存储或账号配置；只增加完成已给出的拉取流程所需的路由与认证。
