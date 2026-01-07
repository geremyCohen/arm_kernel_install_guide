#!/usr/bin/env bash
set -euo pipefail

HOST=""
SSH_USER="ubuntu"
REMOTE_DIR=""
LOCAL_DIR="${HOME}/kernels"
declare -a VERSIONS=()
SSH_FLAGS=(-A -o BatchMode=yes -o StrictHostKeyChecking=accept-new)
REQUIRED_FILES=(Image.gz modules.tar.xz)
OPTIONAL_FILES=(config.stock)

usage() {
  cat <<'USAGE'
Usage: pull_kernel_artifacts.sh --host <ip-or-name> [options]

Options:
  --host <host>             Kernel build host to pull from (required)
  --ssh-user <name>         SSH user on the build host (default: ubuntu)
  --remote-dir <path>       Remote kernels directory (default: ~/work/kernel-builds/fastpath)
  --local-dir <path>        Local destination directory (default: ~/kernels)
  --version <name>          Specific kernel version directory to copy (may be repeated)
  -h, --help                Show this message
USAGE
}

log() { printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2; }
fail() { log "ERROR: $*"; exit 1; }

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --host) HOST="$2"; shift 2 ;;
      --ssh-user) SSH_USER="$2"; shift 2 ;;
      --remote-dir) REMOTE_DIR="$2"; shift 2 ;;
      --local-dir) LOCAL_DIR="$2"; shift 2 ;;
      --version) VERSIONS+=("$2"); shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) fail "Unknown option $1" ;;
    esac
  done
  [[ -n "${HOST}" ]] || fail "--host is required"
}

ssh_cmd() {
  ssh "${SSH_FLAGS[@]}" "${SSH_USER}@${HOST}" "$@"
}

scp_cmd() {
  scp "${SSH_FLAGS[@]}" "$@"
}

get_remote_home() {
  ssh_cmd 'printf %s "$HOME"'
}

resolve_remote_path() {
  local path="$1"
  local remote_home="$2"
  local default_rel="work/kernel-builds/fastpath"
  if [[ -z "${path}" ]]; then
    printf '%s/%s\n' "${remote_home}" "${default_rel}"
    return
  fi
  case "${path}" in
    "~") printf '%s\n' "${remote_home}" ;;
    "~/"*) printf '%s/%s\n' "${remote_home}" "${path:2}" ;;
    *) printf '%s\n' "${path}" ;;
  esac
}

resolve_local_path() {
  local path="$1"
  case "${path}" in
    "~") printf '%s\n' "${HOME}" ;;
    "~/"*) printf '%s/%s\n' "${HOME}" "${path:2}" ;;
    *) printf '%s\n' "${path}" ;;
  esac
}

confirm() {
  log "Pulling kernel artifacts:"
  log "  Host        : ${HOST}"
  log "  SSH user    : ${SSH_USER}"
  log "  Remote dir  : ${REMOTE_DIR}"
  log "  Local dir   : ${LOCAL_DIR}"
  if [[ ${#VERSIONS[@]} -gt 0 ]]; then
    log "  Versions    : ${VERSIONS[*]}"
  else
    log "  Versions    : auto-detected"
  fi
}

ensure_local_dir() {
  mkdir -p "${LOCAL_DIR}"
}

auto_detect_versions() {
  local remote_script remote_cmd
  remote_script=$(cat <<'SCRIPT'
set -euo pipefail
dir="${REMOTE_DIR}"
if [ ! -d "$dir" ]; then exit 0; fi
for path in "$dir"/*; do
  [ -d "$path" ] || continue
  base=$(basename "$path")
  if [ -f "$path/Image.gz" ] && [ -f "$path/modules.tar.xz" ]; then
    printf "%s\n" "$base"
  fi
done
SCRIPT
)
  printf -v remote_cmd 'REMOTE_DIR=%q bash -lc %q' "${REMOTE_DIR}" "${remote_script}"
  mapfile -t DETECTED < <(ssh_cmd "${remote_cmd}")
  if [[ ${#DETECTED[@]} -eq 0 ]]; then
    fail "No kernel directories with required artifacts found under ${REMOTE_DIR}"
  fi
  VERSIONS=("${DETECTED[@]}")
}

needs_copy() {
  local version="$1"
  local missing="false"
  local dest="${LOCAL_DIR}/${version}"
  for file in "${REQUIRED_FILES[@]}"; do
    if [[ ! -f "${dest}/${file}" ]]; then
      missing="true"
      break
    fi
  done
  [[ "${missing}" == "true" ]]
}

copy_version() {
  local version="$1"
  local remote_base="${REMOTE_DIR}/${version}"
  local local_base="${LOCAL_DIR}/${version}"
  mkdir -p "${local_base}"

  for file in "${REQUIRED_FILES[@]}"; do
    local remote_file="${remote_base}/${file}"
    local local_file="${local_base}/${file}"
    if [[ -f "${local_file}" ]]; then
      log "Skipping existing ${version}/${file}"
      continue
    fi
    log "Copying ${version}/${file}"
    ssh_cmd "test -f ${remote_file@Q} || exit 3"
    scp_cmd "${SSH_USER}@${HOST}:${remote_file}" "${local_file}"
  done

  for file in "${OPTIONAL_FILES[@]}"; do
    local remote_file="${remote_base}/${file}"
    local local_file="${local_base}/${file}"
    if ssh_cmd "test -f ${remote_file@Q}"; then
      if [[ -f "${local_file}" ]]; then
        log "Skipping existing optional ${version}/${file}"
        continue
      fi
      log "Copying optional ${version}/${file}"
      scp_cmd "${SSH_USER}@${HOST}:${remote_file}" "${local_file}"
    else
      log "Optional file ${version}/${file} not found on remote; skipping"
    fi
  done
}

main() {
  parse_args "$@"
  LOCAL_DIR="$(resolve_local_path "${LOCAL_DIR}")"
  REMOTE_HOME="$(get_remote_home)"
  REMOTE_DIR="$(resolve_remote_path "${REMOTE_DIR}" "${REMOTE_HOME}")"
  confirm
  ensure_local_dir
  if [[ ${#VERSIONS[@]} -eq 0 ]]; then
    auto_detect_versions
  fi

  local copied_any="false"
  for version in "${VERSIONS[@]}"; do
    if needs_copy "${version}"; then
      copy_version "${version}"
      copied_any="true"
    else
      log "All artifacts for ${version} already present; skipping"
    fi
  done

  if [[ "${copied_any}" == "false" ]]; then
    log "Nothing to copy; all requested versions already available."
  else
    log "Artifact pull complete."
  fi
}

main "$@"
