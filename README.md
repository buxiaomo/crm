# Container Registry Mirrors

一个无缓存的公开镜像加速器，支持 Docker Hub `registry-mirrors` 和 Containerd 白名单内多仓库 mirror，并兼容 HTTP 前向代理与 HTTPS CONNECT 隧道。默认允许的主机包含：

- docker.io / registry-1.docker.io / auth.docker.io / production.cloudfront.docker.com
- gcr.io
- k8s.io / registry.k8s.io
- docker.elastic.co / ghcr.io

## CRM 本地账号认证（可选）

此项为服务端部署运维配置。需要限制 CRM 使用者时，在服务端配置文件加入以下内容，替换为自己的强密码后重启 CRM：

```yaml
auth:
  users:
    admin: "REPLACE_WITH_A_STRONG_PASSWORD"
    # 可继续添加其他用户名和密码
```

省略 `auth`（或设为 `null`）时保持匿名兼容；配置了 `auth` 却没有有效账号时拒绝启动。
启用后，mirror 需要认证；未携带或错误凭据返回
`401`，并带 CRM 自己的 Basic 认证挑战。每个请求重新校验，不创建登录会话。
仅普通 `GET /`、`GET /healthz` 和 `GET /metrics` 允许匿名访问；其他方法、路径和前向代理请求仍要求认证。
首页根据实际加载的配置显示认证状态；启用时提示未授权无法使用镜像加速，关闭时说明允许匿名访问。
首页保留默认及自定义仓库白名单，不展示账号密码或服务端账号配置；监控接口会公开请求量、流量、错误率、连接数和运行时间等聚合信息。

支持这种 URL 形式：`https://用户名:密码@mirrors.example.com/v2/...`，
前提是客户端支持 URL userinfo，并将其转换为 `Authorization: Basic ...`。
特殊字符需要 URL 编码。更适合日常验证的方式是交互输入密码：

```bash
curl --user admin \
  'https://mirrors.example.com/v2/buxiaomo/kubeasy/manifests/v1.34.12?ns=ghcr.io'
```

只提供用户名时，curl 会提示输入密码，详见 [curl 文档](https://curl.se/docs/manpage.html#-u)。
CRM 校验后删除这组凭据；上游 token、Registry 和 CDN 不会收到本地账号密码。
CRM 仍然只匿名拉取公开镜像，本地认证不会授予上游私有镜像访问权限。

兼容的 HTTP/CONNECT 前向代理使用 **Proxy-Authorization** 认证，缺少或错误时返回
`407 + Proxy-Authenticate`。例如 CRM 使用 TCP 模式（`listen: ":8888"`）时，本机代理可用：

```bash
curl --proxy http://127.0.0.1:8888 --proxy-user admin https://ghcr.io/v2/
```

CRM 会移除代理凭据，保留请求原本面向上游的 `Authorization`；MITM 模式先认证
CONNECT 隧道，不要求在隧道内部重复发送 CRM 凭据。

Basic 和 Base64 不提供加密。对外通过 HTTPS 使用；CRM 裸 HTTP 监听仅用于本机或可信内网。
配置文件应限制为服务账号可读（例如 `chmod 600`），
不要把真实密码写进 Git 或分享含密码的 URL。已有 Nginx/Caddy 配置默认透传认证头，
无需在前端再次配置另一套密码。

## Docker 镜像加速器（推荐）

本节示例适用于匿名访问。CRM 启用 Basic 认证时，需单独验证 Docker Engine 的认证支持；
`registry-mirrors` 能否携带 URL 凭据不能由 curl 成功推断。

将以下配置合并到客户端的 `/etc/docker/daemon.json`：

```json
{
  "registry-mirrors": ["https://mirrors.example.com"]
}
```

`mirrors.example.com` 应指向部署了 CRM 的 HTTPS 入口，镜像名称保持不变：

```bash
sudo systemctl restart docker
docker pull nginx
```

客户端无需配置 HTTP/HTTPS 代理，也无需启用 MITM。
服务端获取匿名 `pull` 令牌，并跟随允许的 blob CDN 跳转后流式返回。
这部分认证和下载不要求客户端直连 `auth.docker.io` 或 CDN。

- Docker Engine 的 `registry-mirrors` 仅用于 Docker Hub；Containerd 的多仓库配置见下节。仅支持公开镜像只读拉取，不支持推送或私仓。
- 不缓存镜像或令牌；每次资源请求重新获取令牌，增加一次认证往返。
  服务端承担下载流量和 Docker Hub 匿名额度，客户端登录凭证不会转发。
- 清单内容保持原样；清单内的外部 `urls` / foreign layer 下载不在支持保证内。

Docker Desktop 可在 Docker Engine 设置中合并相同 JSON 后应用。
参见 [Docker mirror 文档](https://docs.docker.com/docker-hub/image-library/mirror/)。

## Containerd 镜像加速器

Kubernetes / CRI 客户端先在 `/etc/containerd/config.toml` 中启用 hosts 配置目录。
按现有配置版本合并对应片段，保留其余配置；`version` 是文件顶层字段。

Containerd 1.5+ 的 1.x 版本（配置版本 2）：

```toml
version = 2

[plugins."io.containerd.grpc.v1.cri".registry]
  config_path = "/etc/containerd/certs.d"
```

Containerd 2.x（配置版本 3）：

```toml
version = 3

[plugins."io.containerd.cri.v1.images".registry]
  config_path = "/etc/containerd/certs.d"
```

Containerd 2.x 若仍使用配置版本 2，可沿用第一种插件路径；
不要只改顶层 `version` 而保留不匹配的插件配置。

创建 `/etc/containerd/certs.d/docker.io/hosts.toml`：

```toml
server = "https://registry-1.docker.io"

[host."https://mirrors.example.com"]
  capabilities = ["pull", "resolve"]
```

这里的域名应是自己信任的 CRM 入口；`resolve` 允许其解析 tag 对应的 digest。
上例在加速器失败时会回退 Docker Hub；如需禁止直连回退，
将 `server` 也改为 `https://mirrors.example.com`。

GHCR 与 GCR 使用同一个 CRM 地址，分别创建以下文件：

`/etc/containerd/certs.d/ghcr.io/hosts.toml`：

```toml
server = "https://ghcr.io"

[host."https://mirrors.example.com"]
  capabilities = ["pull", "resolve"]
```

`/etc/containerd/certs.d/gcr.io/hosts.toml`：

```toml
server = "https://gcr.io"

[host."https://mirrors.example.com"]
  capabilities = ["pull", "resolve"]
```

如果 CRM 要求账号认证，在上述各仓库的 `hosts.toml` 中，为 **CRM host** 添加以下请求头。
Containerd 不会从 host URL 中读取用户名和密码，不要使用 `https://用户名:密码@mirrors.example.com`：

```toml
[host."https://mirrors.example.com".header]
  Authorization = "Basic BASE64_OF_USERNAME_COLON_PASSWORD"
```

对不带换行的 `用户名:密码` 做 Base64 编码，将单行结果填入占位符。
不要给上游 host 或全局请求配置这组凭据；CRM 校验后不会将其转发到上游。
Base64 不是加密，必须使用 HTTPS，并限制 `hosts.toml` 为服务账号可读（例如 `chmod 600`）。
参见 [Containerd header 配置](https://github.com/containerd/containerd/blob/main/docs/hosts.md#header-fields)。

Containerd 自动附加 `?ns=ghcr.io` 或 `?ns=gcr.io`，CRM 在白名单内选择上游；
无 `ns` 时仍使用 Docker Hub。仓库地址仅支持 HTTPS 默认端口或 443。
CRM 在服务端处理匿名 Bearer 认证和下载跳转，不转发客户端凭证。
GHCR 下载域名 `pkg-containers.githubusercontent.com` 已内置；其他仓库的认证/CDN 域名
如未放行，需在 CRM 的 `allowed_hosts` 中添加精确域名或带边界的正则。

修改 `config.toml` 后重启 Containerd，并通过 CRI 验证：

```bash
sudo systemctl restart containerd
sudo crictl --runtime-endpoint unix:///run/containerd/containerd.sock \
  --image-endpoint unix:///run/containerd/containerd.sock \
  pull docker.io/library/nginx:latest
sudo crictl --runtime-endpoint unix:///run/containerd/containerd.sock \
  --image-endpoint unix:///run/containerd/containerd.sock \
  pull ghcr.io/buxiaomo/kubeasy:v1.34.12
sudo crictl --runtime-endpoint unix:///run/containerd/containerd.sock \
  --image-endpoint unix:///run/containerd/containerd.sock \
  pull gcr.io/distroless/static:nonroot
```

仅修改 `hosts.toml` 无需重启。
单独使用 `ctr` 时，须显式传入 hosts 目录，它不读取 CRI 插件的 mirror 配置：

```bash
sudo ctr images pull --hosts-dir /etc/containerd/certs.d docker.io/library/nginx:latest
```

### Containerd 1.x 旧配置兼容

提交 `9644e9d` 删除的旧式配置可用于仍采用该机制的 Containerd 1.x：

```toml
version = 2

[plugins."io.containerd.grpc.v1.cri".registry.mirrors."docker.io"]
  endpoint = ["https://mirrors.example.com"]
```

这套 CRI 配置已弃用，不与上面的非空 `config_path` 混用；新部署使用 `hosts.toml`。
修改后重启 Containerd，使用上面的 `crictl` 命令验证。
其他白名单仓库可使用对应仓库名称配置同一 endpoint，推荐使用上面的 `hosts.toml`。
详见 [Containerd hosts 配置](https://github.com/containerd/containerd/blob/main/docs/hosts.md)
和 [1.7 旧式配置说明](https://github.com/containerd/containerd/blob/release/1.7/docs/cri/registry.md)。

## 运行

支持通过命令行指定配置文件路径，或在当前目录自动发现。

1) 执行 `cp config.example.yaml config.yaml` 创建本地配置并按需修改（也支持 `config.yml` / 兼容 `config.json`）。
2) 启动服务：

```bash
cd crm
go run .
```

或构建二进制：

```bash
go build -o crm
./crm
```

也可以通过命令行指定配置文件：

```bash
./crm -config /path/to/config.yaml
# 或别名：
./crm -c /path/to/config.yaml
```

## 配置文件

推荐使用 YAML：复制示例 `config.example.yaml` 为本地 `config.yaml` 并根据需要修改。本地 `config.yaml` 已被 Git 忽略，不应提交。程序会优先读取当前目录的 `config.yaml` / `config.yml`，其次读取 `config.json`；也可通过命令行 `-config` 指定路径。若未找到配置文件，程序会直接退出并提示错误。

配置项说明：

- `domain`: 首页 Docker、Containerd 和前向代理示例使用的 CRM 主机名；省略或空字符串时为 `mirrors.example.com`。
  仅填写 ASCII 主机名，不带协议、端口、路径或末尾点；每段最多 63 字符，总长最多 253 字符，国际化域名请使用 Punycode。
  域名须包含点号（`localhost` 除外），避免 Docker 将其解析为 Hub 命名空间。
  只影响首页示例，不改变监听地址、上游或白名单。
- `auth.users`: 可选的 CRM 本地账号密码映射；配置后镜像拉取和代理要求认证，首页与监控的普通 GET 请求公开，详见上文。
- `listen`: 唯一监听入口。端口或 TCP 地址（如 `8888`、`:8888`、`127.0.0.1:8888`、`[::1]:8888`）使用 TCP；绝对路径（如 `/run/crm.sock`）使用 Unix socket。不能为空，不支持相对 socket 路径，不会同时开启两种入口。socket 目录须存在；启动时仅清理确认无监听进程的旧 socket，拒绝覆盖普通文件、符号链接或正在使用的 socket。同一路径只应由一个服务实例管理。
- `allowed_hosts`: 在默认白名单基础上追加前向代理及非 Hub mirror 的仓库、认证和下载主机，支持正则表达式（不区分大小写）；Hub mirror 保留固定认证/CDN 范围。
  - 普通域名按“精确匹配”处理，例如 `docker.io`；点号不会触发正则匹配，也不会自动放行子域名。
  - 使用正则元字符时按正则匹配，例如 `^.*\.k8s\.io$` 匹配所有以 `.k8s.io` 结尾的域名。
- `insecure_tls`: 上游 TLS 是否跳过证书校验（默认 false）
- `log_level`: 日志级别（统一控制日志详细程度），支持 `debug` 或 `info`。
- `mitm`: MITM（中间人）模式配置，用于解密 HTTPS 流量以便调试
  - `enabled`: 是否启用 MITM 模式（默认 false）
  - `ca_cert_path`: CA 证书路径（必填，启用 MITM 时）
  - `ca_key_path`: CA 私钥路径（必填，启用 MITM 时）
- `security.max_request_size`: HTTP 及 MITM 解密后请求体的最大字节数，包括分块传输；透明 CONNECT 的加密流量无法按 HTTP 请求体计量。
- `security.request_timeout`: HTTP 请求或 CONNECT 隧道的总时限，例如 `30m`；TCP 和 Unix socket 入口均使用该配置。请求头读取时限为 30 秒。
- `security.max_header_size`: HTTP 入口请求头上限（字节）。
- `security.max_concurrent_reqs`: 最大并发 HTTP 请求或 CONNECT 隧道数。

以下配置二选一。TCP 模式：

```yaml
listen: ":8888"  # 也可写为 "8888" 或 "127.0.0.1:8888"
```

Unix socket 模式（仓库默认）：

```yaml
listen: "/run/crm.sock"
```

升级旧配置时，删除 `socket_path`。如果原先使用 socket，将其路径移到 `listen`；若保留 `listen: ":8888"`，则只启动 TCP，旧 `socket_path` 不再生效。

### 修改首页域名

在实际使用的配置文件中设置：

```yaml
domain: "mirrors.example.com"
```

替换为自己的 CRM 主机名后重启服务（systemd 部署使用 `sudo systemctl restart crm`），
首页所有 CRM 地址即可更新，无需修改源码或重新编译。
配置仅在启动时读取；不自动修改 DNS、证书、Caddy/Nginx 或客户端现有配置。
首页 mirror 示例使用 HTTPS，前向代理示例仍使用 HTTP 和 `:8888`。

## 前向代理使用示例（兼容可选）

需要前向代理时，先将 CRM 设置为 TCP 模式（例如 `listen: ":8888"`），客户端连接代理服务器的 HTTP 端口。Docker Hub 镜像加速请优先使用上面的 `registry-mirrors` 配置。

下例中的 `mirrors.example.com:8888` 应替换为实际代理地址；同机运行可使用 `127.0.0.1:8888`。

### curl

```bash
curl -v -x http://mirrors.example.com:8888 https://registry-1.docker.io/v2/
```

CRM 启用本地认证时，上例需增加 `--proxy-user 用户名` 并按提示输入密码，否则会先收到 CRM 的 `407 Proxy Authentication Required`。
请求到达上游后，Docker Registry 返回 `401 Unauthorized` 是正常的认证挑战，可用于确认代理连通性。

### Docker Engine

将以下配置合并到 `/etc/docker/daemon.json`：

```json
{
  "proxies": {
    "http-proxy": "http://mirrors.example.com:8888",
    "https-proxy": "http://mirrors.example.com:8888",
    "no-proxy": "localhost,127.0.0.1"
  }
}
```

```bash
sudo systemctl restart docker
docker pull nginx:latest
```

HTTPS 目标也使用 `http://` 代理地址，由 CONNECT 建立 TLS 隧道。Docker Desktop 请通过应用设置配置代理。参见 [Docker 官方代理配置](https://docs.docker.com/engine/daemon/proxy/)。

### Containerd

运行 `sudo systemctl edit containerd`，添加：

```ini
[Service]
Environment="HTTP_PROXY=http://mirrors.example.com:8888"
Environment="HTTPS_PROXY=http://mirrors.example.com:8888"
Environment="NO_PROXY=localhost,127.0.0.1"
```

```bash
sudo systemctl daemon-reload
sudo systemctl restart containerd
```

对于 Kubernetes 集群，将需要直连的内网域名、节点和服务网段加入 `NO_PROXY`。如果单独运行 `ctr`，还应给该命令设置相同的代理环境变量。

### 白名单与反向代理部署

拉取镜像会访问认证服务器及下载重定向地址。这些地址也必须在 `allowed_hosts` 中；按实际仓库添加精确域名或带边界的正则，避免使用无限制通配。Docker 的相关域名可参考[官方白名单](https://docs.docker.com/desktop/setup/allow-list/)。

仓库中的 `Caddy` 和 `nginx.conf` 提供 mirror API、首页、健康检查和指标入口；`registry-mirrors` 指向该 HTTPS 域名。示例与 `config.example.yaml` 统一使用 `/run/crm.sock`，目录须存在且服务用户可写，反向代理用户须能访问 socket。nginx 示例关闭响应缓冲，避免镜像层写入临时文件。

这些普通反向代理配置不提供 CONNECT 隧道。socket 模式不开放 TCP 端口；需要前向代理时，将 `listen` 改为 TCP 地址，并将 Caddy 的 `reverse_proxy` 或 nginx 的 `upstream` 地址改为 `127.0.0.1:8888`（端口与 CRM 配置保持一致），客户端再连接 CRM 的端口。

## MITM 模式

镜像加速器不需要 MITM；以下仅用于前向代理调试。

MITM（中间人）模式允许代理解密 HTTPS 流量，用于调试和分析容器镜像拉取过程中的问题。携带请求体的 MITM 请求在响应后关闭隧道，后续请求重新建连；无请求体的请求仍可复用连接。

### 准备 CA 证书

使用 OpenSSL 生成 CA 证书和私钥：

```bash
# 生成 CA 私钥
openssl genrsa -out ca.key 2048

# 生成 CA 证书
openssl req -new -x509 -key ca.key -out ca.crt -days 3650 -subj "/CN=Container Registry Mirror CA"
```

或使用 mkcert 工具（更简单）：

```bash
mkcert -install
cp "$(mkcert -CAROOT)/rootCA.pem" ca.crt
cp "$(mkcert -CAROOT)/rootCA-key.pem" ca.key
```

### 配置 MITM 模式

在 `config.yaml` 中添加：

```yaml
mitm:
  enabled: true
  ca_cert_path: /path/to/ca.crt
  ca_key_path: /path/to/ca.key
```

### 信任 CA 证书

在使用 MITM 模式前，必须在客户端系统信任 CA 证书：

#### macOS

```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ca.crt
```

#### Linux

```bash
# Debian/Ubuntu
sudo cp ca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates

# CentOS/RHEL
sudo cp ca.crt /etc/pki/ca-trust/source/anchors/
sudo update-ca-trust
```

#### Docker/Containerd

对于容器运行时，需要在容器运行时环境中信任 CA 证书：

```bash
# 对于 Docker
sudo mkdir -p /etc/docker/certs.d/registry-1.docker.io
sudo cp ca.crt /etc/docker/certs.d/registry-1.docker.io/ca.crt
sudo systemctl restart docker

# 对于 Containerd
sudo mkdir -p /etc/containerd/certs.d/registry-1.docker.io
sudo cp ca.crt /etc/containerd/certs.d/registry-1.docker.io/ca.crt
sudo systemctl restart containerd
```

### 验证 MITM 模式

启用 MITM 模式并设置日志级别为 debug 后，可以通过以下命令验证：

```bash
# 使用 curl 测试
curl -v --cacert ca.crt https://registry-1.docker.io/v2/ -x http://localhost:8888

# 或使用 Docker 拉取镜像
docker pull nginx:latest
```

在代理日志中，您将看到解密后的 HTTPS 请求和响应详情。

## 健康检查

HTTP `GET /healthz` 返回 JSON 状态：正常时为 `200`，高负载或累计错误率过高时为 `503`。`GET /metrics` 返回文本指标。

## 开发验证

```bash
go test ./...
go test -race ./...
go vet ./...
make build
```

`make build` 生成 Linux amd64 二进制；本机运行请使用上面的 `go build`。

### 监听入口 E2E

```bash
bash tests/e2e-listener.sh
```

需要 Go、Bash 和 curl。脚本构建本机二进制，使用随机 TCP 端口和临时 Unix socket 验证单入口监听、健康检查、错误配置、活动 socket 保护和退出清理；还会在同一二进制下更改域名配置并重启，验证首页八处地址及请求 Host 隔离。无需 Docker 或外网。

### 隔离 Docker 拉取 E2E

`tests/e2e-mirror.sh` 需要可用的 Docker CLI/daemon 和 `--privileged` dind 容器支持。
默认使用 `docker:29-dind`，宿主 Docker 须已具备或能够拉取该镜像。
先启动本机 CRM，使其 TCP 端口可经 `host.docker.internal` 访问
（例如 `listen: ":8888"`），且 CRM 可访问 Hub 认证、Registry 和 CDN。

```bash
MIRROR_URL=http://host.docker.internal:8888 bash tests/e2e-mirror.sh
```

`MIRROR_URL` 必须使用 `http(s)://host.docker.internal[:port]`，不带路径或凭证。
可用 `DIND_IMAGE` / `TEST_IMAGE` 覆盖镜像，默认测试 `nginx:latest`。
Docker 可能在 mirror 失败后回退直连，因此脚本先以坏 mirror 和黑洞出口代理做阴性对照，
再用全新 dind 容器验证 CRM 拉取及摘要，避免“拉取成功”掩盖回退。
脚本不修改宿主 daemon 配置，不暴露 dind API；结束后清理容器和网络并保留日志。

### 隔离 Containerd / CRI 多仓库 E2E

`tests/e2e-containerd-mirror.sh` 使用独立的 privileged Alpine 容器安装 Containerd 和 crictl，
需要容器可访问 Alpine 软件源，以及本机 CRM 可访问三仓库的认证与下载端点。

```bash
MIRROR_URL=http://host.docker.internal:8888 bash tests/e2e-containerd-mirror.sh
```

脚本先验证坏 mirror 和黑洞出口代理使拉取失败，再用全新运行时和内容存储，
通过 `crictl pull` 拉取 Docker Hub、GHCR、GCR 并检查镜像摘要。
可用 `ALPINE_IMAGE`、`HUB_IMAGE`、`GHCR_IMAGE`、`GCR_IMAGE` 覆写测试镜像。
结束后只清理本次容器和网络，保留日志；不修改宿主 Docker 或 Containerd 配置。
认证失败、标签不存在和上游限流会保留为真实失败，不能用客户端直连回退判断修复成功。
