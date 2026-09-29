# CRM 首页域名配置设计

## 目标

在现有配置文件加入一个 `domain` 字段，首页所有 CRM 地址由该字段生成。
用户修改配置并重启同一个 CRM 二进制即可切换域名，无需修改源码或重新编译。
延续已有范围：只替换 CRM 服务地址，真实上游和外部参考链接不变。

## 行为与实现

- YAML/YML 与 JSON 共用 `Config.Domain`；示例为 `domain: "mirrors.example.com"`。
- 缺省或空字符串沿用 `mirrors.example.com`，兼容已有配置。
- `domain` 是不带协议、端口、路径、查询参数或凭据的 ASCII 主机名。
  按 DNS 标签校验字符、连字符位置、63 字符标签和 253 字符总长；
  域名须含点号（`localhost` 除外），支持 Punycode，不做 DNS 查询。
  拒绝普通单标签主机，避免 Docker 将拉取前缀解释成 Hub 命名空间。
- 在已有 `Config.Validate` 拒绝不合法输入，避免首页生成错误命令或注入内容。
- `newProxyHandler` 保存域名并集中处理缺省值；首页现有静态说明块用一次
  `fmt.Fprintf` 重复引用经过 `html.EscapeString` 的域名，无新模板文件或依赖。
- 覆盖 Docker mirror/login/pull、Containerd host/header，以及前向代理三个地址。
  HTTPS mirror 和 HTTP 前向代理 `:8888` 的现有协议与端口规则保持不变。
- 不根据请求 Host 或转发请求头推导域名；不改监听、上游白名单和认证行为。
- 沿用启动时加载，不添加热加载、额外域名配置项或自动修改 Caddy/Nginx 的逻辑。
  反向代理域名、证书与 DNS 由部署者同步维护。

## 验收与设计自查

单元测试从 YAML/YML/JSON 加载配置并检查实际首页八处地址，覆盖缺省、自定义、
不同请求 Host 和启用认证情况；非法主机名须在配置校验失败。
扩展现有监听 E2E，只构建一次，串行更换配置并重启进程，验证首页随配置变化。
不新增 Docker 环境，不增加通用配置系统；全部写入隔离分支并本地提交，不推送。

Docker 主机名识别依据：[distribution/reference](https://github.com/distribution/reference/blob/main/normalize.go)。
