#!/bin/bash
# Verify real CRI pulls through CRM, with direct registry access blocked.
# MIRROR_URL=http://host.docker.internal:8888 bash tests/e2e-containerd-mirror.sh
set -euo pipefail

: "${MIRROR_URL:?Set MIRROR_URL to http(s)://host.docker.internal[:port]}"
readonly ALPINE_IMAGE="${ALPINE_IMAGE:-alpine:3.23}"
readonly HUB_IMAGE="${HUB_IMAGE:-docker.io/library/busybox:1.37}"
readonly GHCR_IMAGE="${GHCR_IMAGE:-ghcr.io/stargz-containers/busybox:1.32.0-org}"
readonly GCR_IMAGE="${GCR_IMAGE:-gcr.io/distroless/static:nonroot}"
readonly CRI_ENDPOINT='unix:///run/crm-containerd/containerd.sock'
mirror_url="${MIRROR_URL%/}"
if [[ ! "${mirror_url}" =~ ^https?://host[.]docker[.]internal(:[0-9]+)?$ ]]; then
  echo 'MIRROR_URL must use host.docker.internal without path or credentials.' >&2
  exit 1
fi
if [[ "${HUB_IMAGE}" != docker.io/* || "${GHCR_IMAGE}" != ghcr.io/* ||
      "${GCR_IMAGE}" != gcr.io/* ]]; then
  echo 'Image overrides must retain their docker.io, ghcr.io or gcr.io registry.' >&2
  exit 1
fi
command -v docker >/dev/null
log_dir="$(mktemp -d "${TMPDIR:-/tmp}/crm-containerd-e2e.XXXXXX")"
readonly log_dir
readonly run_id="${log_dir##*/}"
network_id=''
active_container=''
phase='setup'

cleanup() {
  local status=$?
  local log_file
  trap - EXIT
  if [[ -n "${active_container}" ]]; then
    docker logs "${active_container}" \
      >"${log_dir}/${phase}.daemon.log" 2>&1 || true
    docker rm -fv "${active_container}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${network_id}" ]]; then
    docker network rm "${network_id}" >/dev/null 2>&1 || true
  fi
  if (( status != 0 )); then
    for log_file in "${log_dir}"/*.log; do
      [[ -f "${log_file}" ]] || continue
      printf '\n%s\n' "${log_file}" >&2
      tail -n 80 "${log_file}" >&2
    done
  fi
  printf 'E2E logs: %s\n' "${log_dir}"
  exit "${status}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

network_id="$(docker network create "${run_id}")"

start_daemon() {
  local endpoint="$1"
  local deadline
  local docker_args=(
    --privileged --network "${network_id}" --name "${run_id}-${phase}"
    --env "MIRROR_ENDPOINT=${endpoint}"
  )
  if [[ "$(uname -s)" == 'Linux' ]]; then
    docker_args+=(--add-host host.docker.internal:host-gateway)
  fi
  # No host mounts or runtime socket: each phase has fresh image storage.
  active_container="$(docker create "${docker_args[@]}" "${ALPINE_IMAGE}" \
    sh -ec '
      # Install before blocking egress. Both packages need Alpine community.
      timeout 180 apk add --no-cache containerd cri-tools ca-certificates
      containerd --version
      case "$(uname -m)" in
        x86_64) platform=linux/amd64 ;;
        aarch64) platform=linux/arm64 ;;
        *) echo "Unsupported test platform: $(uname -m)" >&2; exit 1 ;;
      esac
      mkdir -p /run/crm-containerd /etc/crm-containerd/certs.d
      cat > /etc/crm-containerd/config.toml <<EOF
version = 3
root = "/var/lib/crm-containerd"
state = "/run/crm-containerd"
required_plugins = ["io.containerd.grpc.v1.cri"]
[grpc]
  address = "/run/crm-containerd/containerd.sock"
[plugins."io.containerd.cri.v1.images"]
  snapshotter = "native"
[plugins."io.containerd.cri.v1.images".registry]
  config_path = "/etc/crm-containerd/certs.d"
[plugins."io.containerd.grpc.v1.cri"]
  disable_tcp_service = true
[[plugins."io.containerd.transfer.v1.local".unpack_config]]
  platform = "${platform}"
  snapshotter = "native"
EOF
      for registry in docker.io ghcr.io gcr.io; do
        upstream="https://${registry}"
        if [ "${registry}" = docker.io ]; then
          upstream=https://registry-1.docker.io
        fi
        mkdir -p "/etc/crm-containerd/certs.d/${registry}"
        cat > "/etc/crm-containerd/certs.d/${registry}/hosts.toml" <<EOF
server = "${upstream}"
[host."${MIRROR_ENDPOINT}"]
  capabilities = ["pull", "resolve"]
EOF
      done
      export HTTP_PROXY=http://127.0.0.1:9 HTTPS_PROXY=http://127.0.0.1:9
      export http_proxy="${HTTP_PROXY}" https_proxy="${HTTPS_PROXY}"
      export NO_PROXY=host.docker.internal no_proxy=host.docker.internal
      exec containerd --config /etc/crm-containerd/config.toml --log-level debug
    ')"
  docker start "${active_container}" >/dev/null
  # Includes the bounded package installation and CRI startup.
  deadline=$((SECONDS + 240))
  until docker exec "${active_container}" timeout 5 crictl \
    --runtime-endpoint "${CRI_ENDPOINT}" --image-endpoint "${CRI_ENDPOINT}" \
    --timeout 2s info >"${log_dir}/${phase}.ready.log" 2>&1; do
    if (( SECONDS >= deadline )); then
      echo "${phase}: package installation or CRI startup exceeded 240 seconds." >&2
      return 1
    fi
    if [[ "$(docker inspect --format '{{.State.Running}}' \
      "${active_container}")" != true ]]; then
      echo "${phase}: container exited during package installation/CRI startup." >&2
      return 1
    fi
    sleep 1
  done
}

cri() {
  docker exec "${active_container}" timeout 310 crictl \
    --runtime-endpoint "${CRI_ENDPOINT}" --image-endpoint "${CRI_ENDPOINT}" \
    --timeout 300s "$@"
}

remove_daemon() {
  docker logs "${active_container}" >"${log_dir}/${phase}.daemon.log" 2>&1
  docker rm -fv "${active_container}" >/dev/null
  active_container=''
}

phase='negative'
echo 'Negative control: unavailable mirror and blocked registry fallback.'
start_daemon 'http://127.0.0.1:9'
if cri pull "${HUB_IMAGE}" >"${log_dir}/${phase}.pull.log" 2>&1; then
  echo 'Negative control unexpectedly pulled the image.' >&2
  exit 1
fi
docker logs "${active_container}" >"${log_dir}/${phase}.daemon.log" 2>&1
if ! grep -Eq \
  '(registry-1|auth)[.]docker[.]io.*proxyconnect.*127[.]0[.]0[.]1:9' \
  "${log_dir}/${phase}.daemon.log" "${log_dir}/${phase}.pull.log"; then
  echo 'Negative control did not prove Hub fallback hit the blackhole proxy.' >&2
  exit 1
fi
remove_daemon

phase='positive'
start_daemon "${mirror_url}"
for image in "${HUB_IMAGE}" "${GHCR_IMAGE}" "${GCR_IMAGE}"; do
  registry="${image%%/*}"
  printf 'Positive control: CRI pulling %s through %s.\n' "${image}" "${mirror_url}"
  cri pull "${image}" 2>&1 | tee "${log_dir}/${phase}.${registry}.pull.log"
  cri inspecti --output go-template \
    --template '{{range .status.repoDigests}}{{println .}}{{end}}' "${image}" \
    | tee "${log_dir}/${phase}.${registry}.inspect.log"
  if ! grep -Eq '^.+@sha256:[a-f0-9]{64}$' \
    "${log_dir}/${phase}.${registry}.inspect.log"; then
    echo "${registry}: CRI image inspection did not return a repository digest." >&2
    exit 1
  fi
done
remove_daemon
echo 'PASS: CRI pulled Docker Hub, GHCR and GCR images through CRM.'
