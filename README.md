# Container Registry Mirrors

一个无缓存的 Docker Hub 公开镜像加速器，支持 `registry-mirrors`，并兼容 HTTP 前向代理与 HTTPS CONNECT 隧道。前向代理可限制允许的主机，默认包含：

- docker.io / registry-1.docker.io / auth.docker.io / production.cloudfront.docker.com
- gcr.io
- k8s.io / registry.k8s.io
- docker.elastic.co / ghcr.io

## Docker 镜像加速器（推荐）

将以下配置合并到客户端的 `/etc/docker/daemon.json`：

```json
{
  "registry-mirrors": ["https://mirrors.xiaomo.site"]
}
```

`mirrors.xiaomo.site` 应指向部署了 CRM 的 HTTPS 入口，镜像名称保持不变：

```bash
sudo systemctl restart docker
docker pull nginx
```

客户端无需配置 HTTP/HTTPS 代理，也无需启用 MITM。
服务端获取匿名 `pull` 令牌，并跟随允许的 blob CDN 跳转后流式返回。
这部分认证和下载不要求客户端直连 `auth.docker.io` 或 CDN。

- 仅支持 Docker Hub 公开镜像的只读拉取，不支持推送、私仓或多仓库 mirror。
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

[host."https://mirrors.xiaomo.site"]
  capabilities = ["pull", "resolve"]
```

这里的域名应是自己信任的 CRM 入口；`resolve` 允许其解析 tag 对应的 digest。
上例在加速器失败时会回退 Docker Hub；如需禁止直连回退，
将 `server` 也改为 `https://mirrors.xiaomo.site`。
修改 `config.toml` 后重启 Containerd，并通过 CRI 验证：

```bash
sudo systemctl restart containerd
sudo crictl --runtime-endpoint unix:///run/containerd/containerd.sock \
  --image-endpoint unix:///run/containerd/containerd.sock \
  pull docker.io/library/nginx:latest
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
  endpoint = ["https://mirrors.xiaomo.site"]
```

这套 CRI 配置已弃用，不与上面的非空 `config_path` 混用；新部署使用 `hosts.toml`。
修改后重启 Containerd，使用上面的 `crictl` 命令验证。
旧示例中的 `gcr.io` 不适用：当前 CRM 加速器仅支持 Docker Hub 公开镜像。
详见 [Containerd hosts 配置](https://github.com/containerd/containerd/blob/main/docs/hosts.md)
和 [1.7 旧式配置说明](https://github.com/containerd/containerd/blob/release/1.7/docs/cri/registry.md)。

## 运行

支持通过命令行指定配置文件路径，或在当前目录自动发现。

1) 在工作目录准备 `config.yaml`（或 `config.yml` / 兼容 `config.json`）。
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

推荐使用 YAML：复制示例 `config.yaml` 并根据需要修改。程序会优先读取当前目录的 `config.yaml` / `config.yml`，其次读取 `config.json`；也可通过命令行 `-config` 指定路径。若未找到配置文件，程序会直接退出并提示错误。

配置项说明：
- `listen`: 监听地址，例如 `:8888`
- `socket_path`: 可选 Unix socket 路径，例如 `/run/crm.sock`；启动时仅清理确认无监听进程的旧 socket，拒绝覆盖普通文件、符号链接或正在使用的 socket。同一路径只应由一个服务实例管理。
- `allowed_hosts`: 在默认白名单基础上追加前向代理主机，支持正则表达式（不区分大小写）；不改变 mirror 的固定 Hub/CDN 范围。
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

## 前向代理使用示例（兼容可选）

需要前向代理或访问其他 registry 时，可使用以下兼容配置，客户端连接代理服务器的 HTTP 端口。Docker Hub 镜像加速请优先使用上面的 `registry-mirrors` 配置。

下例中的 `proxy.example.com:8888` 应替换为实际代理地址；同机运行可使用 `127.0.0.1:8888`。

### curl

```bash
curl -v -x http://proxy.example.com:8888 https://registry-1.docker.io/v2/
```

未携带认证信息时，Docker Registry 返回 `401 Unauthorized` 是正常的认证挑战，可用于确认代理连通性。

### Docker Engine

将以下配置合并到 `/etc/docker/daemon.json`：

```json
{
  "proxies": {
    "http-proxy": "http://proxy.example.com:8888",
    "https-proxy": "http://proxy.example.com:8888",
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
Environment="HTTP_PROXY=http://proxy.example.com:8888"
Environment="HTTPS_PROXY=http://proxy.example.com:8888"
Environment="NO_PROXY=localhost,127.0.0.1"
```

```bash
sudo systemctl daemon-reload
sudo systemctl restart containerd
```

对于 Kubernetes 集群，将需要直连的内网域名、节点和服务网段加入 `NO_PROXY`。如果单独运行 `ctr`，还应给该命令设置相同的代理环境变量。

### 白名单与反向代理部署

拉取镜像会访问认证服务器及下载重定向地址。这些地址也必须在 `allowed_hosts` 中；按实际仓库添加精确域名或带边界的正则，避免使用无限制通配。Docker 的相关域名可参考[官方白名单](https://docs.docker.com/desktop/setup/allow-list/)。

仓库中的 `Caddy` 和 `nginx.conf` 提供 mirror API、首页、健康检查和指标入口；`registry-mirrors` 指向该 HTTPS 域名。示例与 `config.yaml` 统一使用 `/run/crm.sock`，目录须存在且服务用户可写，反向代理用户须能访问 socket。nginx 示例关闭响应缓冲，避免镜像层写入临时文件。

这些普通反向代理配置不提供 CONNECT 隧道；使用前向代理的 Docker/Containerd 客户端仍应连接 CRM 的 `8888` 端口。

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
