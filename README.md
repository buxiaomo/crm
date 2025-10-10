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

## 健康检查

HTTP `GET /healthz` 返回 `200 ok`。
