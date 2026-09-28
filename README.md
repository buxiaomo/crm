# Container Registry Mirrors

一个无缓存的前向代理，专为容器镜像 registry 中转：支持 HTTP 代理与 HTTPS CONNECT 隧道。可限制允许的主机，默认包含：

- docker.io / registry-1.docker.io / auth.docker.io / production.cloudfront.docker.com
- gcr.io
- k8s.io / registry.k8s.io
- docker.elastic.co / ghcr.io

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
- `socket_path`: 可选 Unix socket 路径，例如 `/tmp/crm.sock`；启动时仅清理确认无监听进程的旧 socket，拒绝覆盖普通文件、符号链接或正在使用的 socket。同一路径只应由一个服务实例管理。
- `allowed_hosts`: 在默认白名单基础上追加允许代理的主机，支持正则表达式（不区分大小写）。
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

## 使用示例

本服务是**前向代理**，客户端需要连接代理服务器的 HTTP 端口。它不提供 Registry mirror API，不能填入 Docker 的 `registry-mirrors` 或 Containerd 的 registry endpoint。

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

仓库中的 `Caddy` 和 `nginx.conf` 用于展示首页、健康检查和指标；普通 HTTP 反向代理配置不能替代支持 CONNECT 的前向代理。Docker/Containerd 应连接 CRM 的 `8888` 端口。示例 Unix socket 路径统一为 `/tmp/crm.sock`。

## MITM 模式

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
