#!/bin/bash
# Verify real CRM listener startup and shutdown without Docker or external HTTP.
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp_dir="$(mktemp -d /tmp/crm-listener.XXXXXX)"
readonly project_dir tmp_dir
server_pid=''
child_pid=''
phase='build'

fail() {
  printf 'FAIL (%s): %s\n' "${phase}" "$*" >&2
  exit 1
}

cleanup() {
  local status=$? pid file
  trap - EXIT
  for pid in "${server_pid}" "${child_pid}"; do
    [[ -n "${pid}" ]] || continue
    kill -KILL "${pid}" 2>/dev/null || true
    wait "${pid}" 2>/dev/null || true
  done
  if (( status != 0 )); then
    for file in "${tmp_dir}"/*.log; do
      [[ -f "${file}" ]] || continue
      printf '\n%s\n' "${file##*/}" >&2
      tail -n 25 "${file}" >&2
    done
  fi
  rm -rf "${tmp_dir}"
  exit "${status}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

wait_for_exit() {
  local pid="$1" deadline=$((SECONDS + $2))
  while kill -0 "${pid}" 2>/dev/null; do
    (( SECONDS < deadline )) || fail "Process ${pid} did not exit in $2s."
    sleep 0.1
  done
  wait "${pid}"
}

healthy() {
  curl -q --noproxy '*' --fail --silent --show-error \
    --connect-timeout 1 --max-time 2 "$@" >"${tmp_dir}/health.log" 2>&1
}

cd "${project_dir}"
go build -o "${tmp_dir}/crm" . >"${tmp_dir}/build.log" 2>&1 &
child_pid=$!
wait_for_exit "${child_pid}" 120 || fail 'Build failed.'
child_pid=''

for phase in tcp bare_port unix; do
  listen='127.0.0.1:0'
  [[ "${phase}" != bare_port ]] || listen='0'
  [[ "${phase}" != unix ]] || listen="${tmp_dir}/crm.sock"
  printf 'listen: "%s"\n' "${listen}" >"${tmp_dir}/config.yaml"
  log_file="${tmp_dir}/${phase}.log"
  "${tmp_dir}/crm" -config "${tmp_dir}/config.yaml" >"${log_file}" 2>&1 &
  server_pid=$!
  deadline=$((SECONDS + 10))
  while true; do
    kill -0 "${server_pid}" 2>/dev/null || fail 'Server exited before ready.'
    if [[ "${phase}" == unix ]]; then
      curl_args=(--unix-socket "${listen}" 'http://localhost/healthz')
    else
      address="$(sed -n 's/^.*正在监听 TCP //p' "${log_file}")"
      port="${address##*:}"
      host='127.0.0.1'
      [[ "${phase}" != bare_port ]] || host='localhost'
      curl_args=("http://${host}:${port}/healthz")
    fi
    if [[ "${phase}" == unix || "${port}" =~ ^[1-9][0-9]*$ ]] &&
        healthy "${curl_args[@]}"; then
      break
    fi
    (( SECONDS < deadline )) || fail 'Health check did not pass in 10s.'
    sleep 0.1
  done
  [[ "$(grep -c '正在监听' "${log_file}")" == 1 ]] ||
    fail 'Expected exactly one successful listener log.'
  if [[ "${phase}" == unix ]]; then
    grep -Fq "正在监听 Unix socket ${listen}" "${log_file}" ||
      fail 'Expected the configured Unix socket listener.'
    "${tmp_dir}/crm" -config "${tmp_dir}/config.yaml" \
      >"${tmp_dir}/bind.log" 2>&1 &
    child_pid=$!
    if wait_for_exit "${child_pid}" 10; then
      fail 'A second process accepted the active socket.'
    fi
    child_pid=''
    ! grep -q '正在监听' "${tmp_dir}/bind.log" ||
      fail 'Failed binding was logged as successful.'
    grep -q 'socket is already in use' "${tmp_dir}/bind.log" ||
      fail 'Expected active socket rejection.'
    healthy "${curl_args[@]}" || fail 'Original Unix server became unhealthy.'
  else
    grep -Fq "正在监听 TCP ${address}" "${log_file}" ||
      fail 'Expected a TCP listener with an assigned port.'
    [[ "${phase}" != tcp || "${address}" == 127.0.0.1:* ]] ||
      fail 'Expected the configured TCP address.'
  fi
  kill -TERM "${server_pid}"
  wait_for_exit "${server_pid}" 15 || fail 'SIGTERM did not exit successfully.'
  server_pid=''
  [[ ! -e "${tmp_dir}/crm.sock" ]] || fail 'Socket remained after shutdown.'
done

for phase in empty invalid_tcp missing_directory; do
  listen=''
  [[ "${phase}" != invalid_tcp ]] || listen='localhost'
  [[ "${phase}" != missing_directory ]] ||
    listen="${tmp_dir}/missing/crm.sock"
  printf 'listen: "%s"\n' "${listen}" >"${tmp_dir}/config.yaml"
  log_file="${tmp_dir}/${phase}.log"
  "${tmp_dir}/crm" -config "${tmp_dir}/config.yaml" >"${log_file}" 2>&1 &
  child_pid=$!
  if wait_for_exit "${child_pid}" 10; then
    fail 'Invalid configuration exited successfully.'
  fi
  child_pid=''
  grep -q '配置验证失败' "${log_file}" || fail 'Expected validation failure.'
  ! grep -q '正在监听' "${log_file}" || fail 'Invalid config opened a listener.'
  [[ ! -e "${tmp_dir}/crm.sock" && ! -e "${tmp_dir}/missing/crm.sock" ]] ||
    fail 'Invalid configuration created a socket.'
done
echo 'PASS: TCP, bare port, Unix socket, invalid config, bind failure and shutdown.'
