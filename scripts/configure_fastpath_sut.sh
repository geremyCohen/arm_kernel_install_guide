#!/usr/bin/env bash
set -euo pipefail

HOST=""
SSH_USER="ubuntu"
FP_USER="fpuser"
SSH_FLAGS=(-o BatchMode=yes -o StrictHostKeyChecking=accept-new)

usage() {
  cat <<'USAGE'
Usage: configure_fastpath_sut.sh --host <ip-or-name> [options]

Options:
  --host <host>            Target hostname or IP (required)
  -h, --help               Show this message
USAGE
}

log() {
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2
}

fail() {
  log "ERROR: $*"
  exit 1
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --host) HOST="$2"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) fail "Unknown argument: $1" ;;
    esac
  done
  [[ -n "${HOST}" ]] || fail "--host is required"
}

confirm() {
  log "Configuring ${HOST} as fastpath SUT (non-interactive mode)"
}

run_ssh() {
  ssh "${SSH_FLAGS[@]}" "${SSH_USER}@${HOST}" "$@"
}

ensure_packages() {
  log "Ensuring docker.io, btop, and yq are installed"
  run_ssh "sudo apt-get update -y"
  run_ssh "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io btop yq"
}

configure_groups() {
  log "Configuring docker group access"
  run_ssh "sudo groupadd -f docker"
  run_ssh "sudo usermod -aG docker ${SSH_USER}"
}

create_fp_user() {
  log "Creating/updating ${FP_USER}"
  run_ssh "sudo groupadd -f ${FP_USER}"
  run_ssh "if ! id -u ${FP_USER} >/dev/null 2>&1; then sudo useradd -g ${FP_USER} -m ${FP_USER}; fi"
  run_ssh "sudo usermod --shell /bin/bash ${FP_USER}"
  run_ssh "sudo usermod -a -G docker ${FP_USER}"
  run_ssh "sudo usermod -a -G sudo ${FP_USER}"
  run_ssh "echo '${FP_USER} ALL=(ALL) NOPASSWD: ALL' | sudo tee /etc/sudoers.d/${FP_USER} >/dev/null"
  run_ssh "sudo chmod 440 /etc/sudoers.d/${FP_USER}"
}

sync_ssh_keys() {
  log "Copying SSH configuration to ${FP_USER}"
  run_ssh "[ -d /home/${SSH_USER}/.ssh ] || { echo 'Source SSH dir missing'; exit 1; }"
  run_ssh "sudo rsync -a /home/${SSH_USER}/.ssh/ /home/${FP_USER}/.ssh/"
  run_ssh "sudo chown -R ${FP_USER}:${FP_USER} /home/${FP_USER}/.ssh"
  run_ssh "sudo chmod 700 /home/${FP_USER}/.ssh"
  run_ssh "sudo find /home/${FP_USER}/.ssh -type f -exec chmod 600 {} +"
}

test_fpuser_login() {
  log "Testing SSH connectivity for ${FP_USER}"
  ssh "${SSH_FLAGS[@]}" "${FP_USER}@${HOST}" "whoami"
}

main() {
  parse_args "$@"
  confirm
  ensure_packages
  configure_groups
  create_fp_user
  sync_ssh_keys
  test_fpuser_login
  log "Fastpath SUT configuration complete."
  log "Note: ${SSH_USER} may need to re-login for docker group membership to take effect."
}

main "$@"
