#!/bin/bash
# Verify a Docker Hub pull through CRM, with direct Hub access blocked.
# MIRROR_URL=http://host.docker.internal:8888 bash tests/e2e-mirror.sh
set -euo pipefail

: "${MIRROR_URL:?Set MIRROR_URL to http(s)://host.docker.internal[:port]}"
readonly DIND_IMAGE="${DIND_IMAGE:-docker:29-dind}"
readonly TEST_IMAGE="${TEST_IMAGE:-nginx:latest}"
mirror_url="${MIRROR_URL%/}"
if [[ ! "${mirror_url}" =~ ^https?://host[.]docker[.]internal(:[0-9]+)?$ ]]; then
  echo 'MIRROR_URL must use host.docker.internal and contain no path or credentials.' >&2
  exit 1
fi

command -v docker >/dev/null
log_dir="$(mktemp -d "${TMPDIR:-/tmp}/crm-mirror-e2e.XXXXXX")"
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
    docker logs "${active_container}" >"${log_dir}/${phase}.daemon.log" 2>&1 || true
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
    --env HTTP_PROXY=http://127.0.0.1:9
    --env HTTPS_PROXY=http://127.0.0.1:9
    --env NO_PROXY=host.docker.internal
    --env DOCKER_TLS_CERTDIR=
  )
  if [[ "$(uname -s)" == 'Linux' ]]; then
    docker_args+=(--add-host host.docker.internal:host-gateway)
  fi
  # Explicit dockerd arguments keep its API on the container's Unix socket.
  active_container="$(docker create "${docker_args[@]}" "${DIND_IMAGE}" \
    dockerd --host=unix:///var/run/docker.sock \
    --registry-mirror="${endpoint}" --insecure-registry="${endpoint#*://}")"
  docker start "${active_container}" >/dev/null
  deadline=$((SECONDS + 60))
  until docker exec "${active_container}" timeout 5 docker \
    --host=unix:///var/run/docker.sock info >/dev/null 2>&1; do
    if (( SECONDS >= deadline )); then
      echo "${phase}: Docker daemon did not become ready within 60 seconds." >&2
      return 1
    fi
    if [[ "$(docker inspect --format '{{.State.Running}}' "${active_container}")" != 'true' ]]; then
      echo "${phase}: Docker daemon exited before becoming ready." >&2
      return 1
    fi
    sleep 1
  done
}

remove_daemon() {
  docker logs "${active_container}" >"${log_dir}/${phase}.daemon.log" 2>&1
  docker rm -fv "${active_container}" >/dev/null
  active_container=''
}

phase='negative'
echo 'Negative control: unavailable mirror and blocked Docker Hub fallback.'
start_daemon 'http://127.0.0.1:9'
if docker exec "${active_container}" timeout 300 docker --host=unix:///var/run/docker.sock \
  pull "${TEST_IMAGE}" >"${log_dir}/${phase}.pull.log" 2>&1; then
  echo 'Negative control unexpectedly pulled the image.' >&2
  exit 1
fi
# Docker may return the first mirror error to the CLI; fallback errors are in daemon logs.
docker logs "${active_container}" >"${log_dir}/${phase}.daemon.log" 2>&1
if ! grep -Eq '(registry-1|auth)[.]docker[.]io.*proxyconnect.*127[.]0[.]0[.]1:9' "${log_dir}/${phase}.daemon.log"; then
  echo 'Negative control did not prove Docker Hub fallback hit the blackhole proxy.' >&2
  exit 1
fi
remove_daemon

phase='positive'
printf 'Positive control: pulling %s through %s.\n' "${TEST_IMAGE}" "${mirror_url}"
start_daemon "${mirror_url}"
docker exec "${active_container}" timeout 300 docker --host=unix:///var/run/docker.sock \
  pull "${TEST_IMAGE}" 2>&1 | tee "${log_dir}/${phase}.pull.log"
docker exec "${active_container}" docker --host=unix:///var/run/docker.sock \
  image inspect --format '{{json .RepoDigests}}' "${TEST_IMAGE}" \
  | tee "${log_dir}/${phase}.inspect.log"
remove_daemon
echo 'PASS: Docker pulled the image through CRM while Docker Hub fallback was blocked.'
