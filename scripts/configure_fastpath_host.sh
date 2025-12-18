#!/usr/bin/env bash
set -euo pipefail

HOST=""
SSH_USER="ubuntu"
ASSUME_YES="false"
REPO_URL="https://git.gitlab.arm.com/tooling/fastpath.git"
SSH_FLAGS=(-o BatchMode=yes -o StrictHostKeyChecking=accept-new)

usage() {
  cat <<'USAGE'
Usage: configure_fastpath_host.sh --host <ip-or-name> [options]

Options:
  --host <host>       Target fastpath host (required)
  --ssh-user <name>   SSH user with sudo rights (default: ubuntu)
  --assume-yes        Skip confirmation prompt
  -h, --help          Show this message
USAGE
}

log() { printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2; }
fail() { log "ERROR: $*"; exit 1; }

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --host) HOST="$2"; shift 2 ;;
      --ssh-user) SSH_USER="$2"; shift 2 ;;
      --assume-yes) ASSUME_YES="true"; shift ;;
      -h|--help) usage; exit 0 ;;
      *) fail "Unknown option $1" ;;
    esac
  done
  [[ -n "${HOST}" ]] || fail "--host is required"
}

confirm() {
  if [[ "${ASSUME_YES}" == "true" ]]; then return; fi
  read -rp "Configure fastpath host ${HOST}? (y/N): " resp
  [[ "${resp,,}" =~ ^(y|yes)$ ]] || fail "Aborted"
}

ssh_cmd() { ssh "${SSH_FLAGS[@]}" "${SSH_USER}@${HOST}" "$@"; }

setup_packages() {
  log "Installing prerequisites"
  ssh_cmd "sudo apt-get update -y"
  ssh_cmd "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y python3-venv python3-pip git"
}

setup_fastpath() {
  log "Creating virtualenv and cloning fastpath repo"
  ssh_cmd "python3 -m venv ~/venv"
  ssh_cmd "bash -lc 'source ~/venv/bin/activate && if [ -d fastpath ]; then cd fastpath && git pull --ff-only; else git clone ${REPO_URL} fastpath; fi'"
  ssh_cmd "bash -lc 'source ~/venv/bin/activate && pip install -r fastpath/fastpath/requirements.txt'"
}

update_shell_configs() {
  log "Ensuring PATH export in shell startup files"
  local export_line='export PATH=\$HOME/venv/bin:\$HOME/fastpath/fastpath:\$PATH'
  for file in "~/.bashrc" "~/.profile"; do
    ssh_cmd "touch ${file}"
    ssh_cmd "sed -i '/fastpath\\/fastpath/d' ${file}"
    ssh_cmd "grep -qxF \"${export_line}\" ${file} || echo \"${export_line}\" >> ${file}"
  done
}

test_fastpath() {
  log "Testing fastpath CLI"
  ssh "${SSH_FLAGS[@]}" "${SSH_USER}@${HOST}" "source ~/.profile >/dev/null 2>&1 || true; source ~/.bashrc >/dev/null 2>&1 || true; fastpath --help | head -n 1"
}

main() {
  parse_args "$@"
  confirm
  setup_packages
  setup_fastpath
  update_shell_configs
  test_fastpath
  log "Fastpath host setup complete."
}

main "$@"
