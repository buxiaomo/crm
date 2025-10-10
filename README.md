# Container Registry Mirrors

一个无缓存的前向代理，专为容器镜像 registry 中转：支持 HTTP 代理与 HTTPS CONNECT 隧道。可限制允许的主机，默认包含：

- docker.io / registry-1.docker.io
- gcr.io
- k8s.io / registry.k8s.io
- docker.elastic.co

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
- `listen`: 监听地址，例如 `:8080`
- `allowed_hosts`: 允许代理的主机匹配列表，支持正则表达式（不区分大小写）。
  - 简单字符串按“精确匹配”处理，例如 `docker.io`。
  - 使用正则元字符时按正则匹配，例如 `^.*\.k8s\.io$` 匹配所有以 `.k8s.io` 结尾的域名。
- `insecure_tls`: 上游 TLS 是否跳过证书校验（默认 false）
- `log_level`: 日志级别（统一控制日志详细程度），支持 `debug` 或 `info`。
- `mitm`: MITM（中间人）模式配置，用于解密 HTTPS 流量以便调试
  - `enabled`: 是否启用 MITM 模式（默认 false）
  - `ca_cert_path`: CA 证书路径（必填，启用 MITM 时）
  - `ca_key_path`: CA 私钥路径（必填，启用 MITM 时）

## 使用示例

### Docker

`/etc/docker/daemon.json`增加以下内容:

```
{
  "registry-mirrors": ["https://mirrors.xiaomo.site"]
}
```
### Containerd
`/etc/containerd/config.toml`增加以下内容:

```
...
[plugins."io.containerd.grpc.v1.cri".registry.mirrors]
  [plugins."io.containerd.grpc.v1.cri".registry.mirrors."docker.io"]
    endpoint = ["https://mirrors.xiaomo.site"]
  [plugins."io.containerd.grpc.v1.cri".registry.mirrors."gcr.io"]
    endpoint = [ "https://mirrors.xiaomo.site" ]
...
```

## MITM 模式

MITM（中间人）模式允许代理解密 HTTPS 流量，用于调试和分析容器镜像拉取过程中的问题。

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
curl -v --cacert ca.crt https://registry-1.docker.io/v2/ -x http://localhost:8080

# 或使用 Docker 拉取镜像
docker pull nginx:latest
```

在代理日志中，您将看到解密后的 HTTPS 请求和响应详情。

## 健康检查

HTTP `GET /healthz` 返回 `200 ok`。
