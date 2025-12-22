#!/usr/bin/env bash
set -euo pipefail

REPO_URL="https://github.com/geremyCohen/arm_kernel_install_guide.git"
CLONE_DIR="${HOME}/arm_kernel_install_guide"
BRANCH="main"
ASSUME_YES="false"

usage() {
  cat <<'USAGE'
Usage: bootstrap_kernel_builder.sh [options]

Options:
  --repo <url>        Git URL to clone (default: arm_kernel_install_guide)
  --branch <name>     Branch to checkout (default: main)
  --dir <path>        Target directory for the clone (default: ~/arm_kernel_install_guide)
  --assume-yes        Skip confirmation prompt
  -h, --help          Show this help message
USAGE
}

log() { printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2; }
fail() { log "ERROR: $*"; exit 1; }

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --repo) REPO_URL="$2"; shift 2 ;;
      --branch) BRANCH="$2"; shift 2 ;;
      --dir) CLONE_DIR="$2"; shift 2 ;;
      --assume-yes) ASSUME_YES="true"; shift ;;
      -h|--help) usage; exit 0 ;;
      *) fail "Unknown option $1" ;;
    esac
  done
}

confirm() {
  if [[ "${ASSUME_YES}" == "true" ]]; then return; fi
  cat <<EOF
About to install git (if needed) and clone:
  repo   : ${REPO_URL}
  branch : ${BRANCH}
  dir    : ${CLONE_DIR}
EOF
  read -rp "Proceed? (y/N): " resp
  [[ "${resp,,}" =~ ^(y|yes)$ ]] || fail "Aborted by user"
}

ensure_git() {
  if command -v git >/dev/null 2>&1; then
    log "git already installed"
    return
  fi
  log "git not found; installing via apt"
  sudo apt-get update -y
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y git
}

clone_repo() {
  if [[ -d "${CLONE_DIR}/.git" ]]; then
    log "Repository already exists at ${CLONE_DIR}; pulling latest ${BRANCH}"
    git -C "${CLONE_DIR}" fetch origin
    git -C "${CLONE_DIR}" checkout "${BRANCH}"
    git -C "${CLONE_DIR}" pull --ff-only origin "${BRANCH}"
  else
    log "Cloning ${REPO_URL} into ${CLONE_DIR}"
    git clone --branch "${BRANCH}" "${REPO_URL}" "${CLONE_DIR}"
  fi
}

print_next_steps() {
  cat <<EOF

Bootstrap complete!
Next steps:
  cd ${CLONE_DIR}
  ./scripts/kernel_build_and_install.sh --demo-fastpath-builds

Refer to .codex/test_kernel_build.md inside the repo for the full validation matrix.
EOF
}

main() {
  parse_args "$@"
  confirm
  ensure_git
  clone_repo
  print_next_steps
}

main "$@"
