# Containerd 多仓库 mirror 实施计划

> **执行方式：** 使用 superpowers:executing-plans 逐项执行；主 agent 负责实现和验收，子 agent 在不重叠范围内负责 E2E 脚本、只读诊断和最终审查。

**目标：** 修复白名单内 GHCR/GCR 的 `ns` 请求返回 400，并验证完整拉取。

**架构：** 复用 `serveMirror` 和标准库 ReverseProxy，统一 namespace 路由；保留 Hub 流程，其他仓库按 Bearer 挑战匿名认证并跟随受限下载跳转。

**技术栈：** Go 1.27.1、net/http、httptest、Bash、Docker/Containerd/crictl。

**设计：** `docs/superpowers/specs/2026-09-28-containerd-registry-mirror-design.md`

## 全局约束

- 分支 `fix/containerd-registry-mirror`，工作目录 `.worktrees/fix/containerd-registry-mirror`；中文文档随代码提交，不推送。
- 不增加依赖、缓存、私仓支持或路径前缀 API；遵循 Google Go/Shell 规范。
- 白名单、HTTPS、端口、凭证隔离和只读限制不可省略；保留原 Hub CDN 限制。
- 测试使用共享全局配置，不用 `t.Parallel`；运行时 E2E 串行且独立清理资源。

## 审查重点

1. namespace URL 注入、重复/空值、大小写和端口：拒绝表与路由表覆盖。
2. Bearer 参数顺序、恶意 realm、重复参数、scope 提权：认证表覆盖。
3. CDN 跨域及跳回 registry 造成 token 泄漏：下载跳转测试覆盖。
4. 非 Hub 401/403/404/429、无认证 200、超时：错误语义测试覆盖。
5. 客户端回退或缓存掩盖错误：独立 CRI 运行时、黑洞代理和阴性对照覆盖。

### Task 1: 请求路由、认证与协议回归

**文件：** 修改 `mirror.go`、`mirror_test.go`。

**接口：** 保持 `(*ProxyHandler).serveMirror(http.ResponseWriter, *http.Request)` 与 `mirrorTransport.RoundTrip(*http.Request) (*http.Response, error)`；内部复用 token 解码与受限下载，无新增配置。

- [x] 增加 `TestMirrorRegistryPull`，GHCR/GCR/custom registry 的 HEAD/GET 必须访问选定主机，移除 ns、保留路径/query，完整校验 manifest/config/layer 字节和 digest；GCR 200 不访问 token，GHCR challenge 使用真实 repository pull scope。
- [x] 扩展拒绝、认证/跳转和错误测试：非法输入不得访问目标；token 重试仅一次、token 不离开原 registry；原 Hub 回归保持不变。
- [x] 运行 `go test -run TestMirror -count=1 .`，预期新增 GHCR/GCR 测试因 400 失败，记录 RED。
- [x] 实现 namespace 校验、非 Hub 挑战认证和安全跳转；修复共用入口，不给单个镜像加例外。
- [x] 运行 `go test ./...`，预期全部通过；提交实现、测试和设计计划。

### Task 2: Containerd E2E 与配置说明

**文件：** 新增 `tests/e2e-containerd-mirror.sh`；修改 `README.md`、`main.go` 首页与本计划验证记录。

**接口：** E2E 消费 Task 1 的 `/v2/...?...ns=<registry>`；`MIRROR_URL=http(s)://host.docker.internal[:port]` 指向独立本机 CRM，使用 `crictl pull`。

- [x] E2E 提供全新容器/数据目录、三个 certs.d 配置、黑洞代理、坏 mirror 阴性对照和成功后 image inspect；不得改宿主 daemon。
- [x] README/首页同步说明 Docker 与 Containerd 范围、GHCR/GCR 配置、匿名权限及额外 token/CDN 白名单，移除矛盾文案。
- [x] 运行 `go test -race ./...`、`go vet ./...`、`make build` 和 `/bin/bash -n tests/e2e-containerd-mirror.sh`，预期通过。
- [x] 串行运行真实 Containerd E2E，目标三个仓库成功且阴性对照失败；外部失败记录精确原因，不篡改断言。
- [x] 独立子 agent 只读审查，主 agent 复核并验证必要修复；提交文档/E2E/验证记录，不推送。

## 计划自查

已检查设计覆盖、函数签名和任务依赖：Task 2 仅消费 Task 1 HTTP API。复用现有 transport/测试 helper，不引入框架、registry adapter、新配置或无关重构；安全校验为增加出站目标所必需。实现由主 agent 连续执行，E2E 脚本在独立文件并行编写，运行阶段串行。

## 验证记录

- 原分支基线 `go test ./...` 通过（3.101s）。
- RED：原实现下新增 GHCR/GCR/custom registry 路由和认证测试均在出站前返回 400；日志 `/tmp/crm-containerd-red.log`。GREEN：`go test -run TestMirror -count=1 .` 通过（1.304s），全量 `go test ./...` 通过（3.098s）。
- `go test -race ./...` 通过（4.955s），`go vet ./...`、`make build`、`bash -n` 和 `git diff --check` 通过。构建缓存位于 `/tmp/crm-containerd-go-cache`，避开宿主缓存目录写入限制。
- 真实 E2E：Docker 29.8.0，Alpine 3.23，Containerd 2.2.0，cri-tools 1.34.0，Linux arm64；黑洞代理阻断直连，坏 mirror 阴性对照失败且日志证明访问黑洞，正向全新运行时成功拉取三仓库镜像并取得摘要。
  - Docker Hub `library/busybox:1.37`：`sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e`。
  - GHCR `stargz-containers/busybox:1.32.0-org`：`sha256:bde48e1751173b709090c2539fdf12d6ba64e88ec7a4301591227ce925f3c678`。
  - GCR `distroless/static:nonroot`：`sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3`。
- E2E 证据目录：`/var/folders/j0/pgc0_9fn1259w1jn0dg8s9900000gn/T/crm-containerd-e2e.SjCV0P/`；本机 CRM 日志 `/tmp/crm-containerd-mirror-service.log` 记录了三仓库 HEAD/manifest/blob 的 ns 请求与 200。容器和网络已由脚本清理，宿主配置未改。
- 测试环境失败经独立子 agent 只读诊断后修正：删除未被 Alpine crictl 支持的 `--version`；为 native snapshotter 补充 transfer unpack 配置，保留 2.2 默认 transfer 拉取路径。没有放宽成功或阴性对照断言。
- 测试镜像校验：最初候选 GHCR busybox:1.36.0 返回 404，仓库 tags/list 确认唯一可用标签为 1.32.0-org，manifest 支持 amd64/arm64，改用该真实存在的标签。
- 用户样例经修复后的本机 CRM 检查：`ghcr.io/buxiaomo/kubeasy:v1.34.12` HEAD 返回 200，digest `sha256:0e33dfed81dc9a0d854b72d37055e6bbe4977e5a2861431d5a451609b00b1e53`。`ghcr.io/immich-app/immich-server:latest` 和 `gcr.io/google-containers/kube:latest` 均得到上游 404 `MANIFEST_UNKNOWN`，属于镜像/标签问题，不能以此判断路由失败。
- 并行分工：根因 agent 确认入口硬编码和文档矛盾；测试 agent 完成隔离 CRI 脚本并诊断环境错误；全分支独立审查未发现需修复的有影响问题。主 agent 复核全部改动与实际验证输出。
- 完成后将实现、中文设计/计划、文档和 E2E 一并本地提交，便于作为一个完整修复审阅；不推送、不合并 main、不部署生产。
- 未验证边界：未在用户的 Containerd 2.4.1 和线上 HTTPS/Caddy 部署实测；其他白名单注册表仅通过本地可控协议测试，实际 token/CDN 仍可能需要额外白名单。私仓、匿名额度和 foreign layer 外部 URL 保持设计中的限制。
