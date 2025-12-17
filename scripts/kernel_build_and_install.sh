#!/usr/bin/env bash
set -euo pipefail

REPO_DEFAULT="git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git"
BRANCH_DEFAULT="linux-rolling-stable"
TAG_DEFAULT=""
CONFIG_FILE_DEFAULT=""
KERNEL_CMDLINE_DEFAULT=""
APPEND_TO_KERNEL_VERSION_DEFAULT=""
KERNEL_INSTALL_DEFAULT="false"
CHANGE_TO_64K_DEFAULT="false"
FASTPATH_DEFAULT="true"
KERNEL_DIR_DEFAULT="${HOME}/kernels/linux"
OUTPUT_BASE_DEFAULT="${HOME}/kernels"
VENV_PATH_DEFAULT="${HOME}/venv-tuxmake"

REPO="${REPO_DEFAULT}"
BRANCH="${BRANCH_DEFAULT}"
TAG="${TAG_DEFAULT}"
CONFIG_FILE="${CONFIG_FILE_DEFAULT}"
KERNEL_CMDLINE="${KERNEL_CMDLINE_DEFAULT}"
APPEND_TO_KERNEL_VERSION="${APPEND_TO_KERNEL_VERSION_DEFAULT}"
KERNEL_INSTALL="${KERNEL_INSTALL_DEFAULT}"
CHANGE_TO_64K="${CHANGE_TO_64K_DEFAULT}"
FASTPATH="${FASTPATH_DEFAULT}"
KERNEL_DIR="${KERNEL_DIR_DEFAULT}"
OUTPUT_BASE="${OUTPUT_BASE_DEFAULT}"
VENV_PATH="${VENV_PATH_DEFAULT}"
ASSUME_YES="false"

usage() {
  cat <<'USAGE'
Usage: kernel_build_and_install.sh [options]

Options:
  --repo <url>                     Kernel git repo (default: Linux stable repo)
  --branch <name>                  Kernel branch to build (default: linux-rolling-stable)
  --tag <tag>                      Kernel tag to checkout (default: none / latest)
  --config-file <path>             Custom base config to use instead of current kernel config
  --kernel-command-line <string>   Override GRUB kernel command line
  --append-to-kernel-version <str> Text appended to EXTRAVERSION
  --kernel-dir <path>              Path where the kernel repo will live (default: ~/kernels/linux)
  --output-base <path>             Directory where build outputs go (default: ~/kernels)
  --kernel-install <bool>          Install kernel artifacts after build (default: false)
  --change-to-64k <bool>           Enable 64K pages (default: false)
  --fastpath <bool>                Apply fastpath configs (default: true)
  --tag-latest                     Shortcut to clear tag (build latest stable)
  --append <string>                Alias for --append-to-kernel-version
  --venv-path <path>               Python venv for tuxmake (default: ~/venv-tuxmake)
  --assume-yes                     Do not prompt before starting
  -h, --help                       Show this help message

Booleans accept: true/false/yes/no/1/0 (case-insensitive).
USAGE
}

log() {
  printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2
}

fail() {
  log "ERROR: $*"
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "Required command '$1' not found in PATH"
}

parse_bool() {
  case "${1,,}" in
    y|yes|true|1) echo "true" ;;
    n|no|false|0) echo "false" ;;
    *) fail "Invalid boolean: ${1}" ;;
  esac
}

version_in_range() {
  local version="$1"
  local lower="$2"
  local upper="$3"
  if [[ -z "${version}" ]]; then
    return 1
  fi
  if dpkg --compare-versions "${version}" ge "${lower}" && dpkg --compare-versions "${version}" lt "${upper}"; then
    return 0
  fi
  return 1
}

append_fastpath_configs() {
  cat >>"$1" <<'FASTPATH'
CONFIG_NAMESPACES=y
CONFIG_NET_NS=y
CONFIG_PID_NS=y
CONFIG_IPC_NS=y
CONFIG_UTS_NS=y
CONFIG_CGROUPS=y
CONFIG_CGROUP_CPUACCT=y
CONFIG_CGROUP_DEVICE=y
CONFIG_CGROUP_FREEZER=y
CONFIG_CGROUP_SCHED=y
CONFIG_CPUSETS=y
CONFIG_MEMCG=y
CONFIG_KEYS=y
CONFIG_VETH=m
CONFIG_BRIDGE=m
CONFIG_BRIDGE_NETFILTER=m
CONFIG_IP_NF_FILTER=m
CONFIG_IP_NF_MANGLE=m
CONFIG_IP_NF_TARGET_MASQUERADE=m
CONFIG_NETFILTER_XTABLES_LEGACY=y
CONFIG_NETFILTER_XT_MATCH_ADDRTYPE=m
CONFIG_NETFILTER_XT_MATCH_CONNTRACK=m
CONFIG_NETFILTER_XT_MATCH_IPVS=m
CONFIG_NETFILTER_XT_MARK=m
CONFIG_IP_NF_NAT=m
CONFIG_NF_NAT=m
CONFIG_POSIX_MQUEUE=y
CONFIG_CGROUP_BPF=y
CONFIG_USER_NS=y
CONFIG_SECCOMP=y
CONFIG_SECCOMP_FILTER=y
CONFIG_CGROUP_PIDS=y
CONFIG_MEMCG_SWAP=y
CONFIG_BLK_CGROUP=y
CONFIG_BLK_DEV_THROTTLING=y
CONFIG_CGROUP_PERF=y
CONFIG_CGROUP_HUGETLB=y
CONFIG_NET_CLS_CGROUP=m
CONFIG_CGROUP_NET_PRIO=y
CONFIG_CFS_BANDWIDTH=y
CONFIG_FAIR_GROUP_SCHED=y
CONFIG_IP_NF_TARGET_REDIRECT=m
CONFIG_IP_VS=m
CONFIG_IP_VS_NFCT=y
CONFIG_IP_VS_PROTO_TCP=y
CONFIG_IP_VS_PROTO_UDP=y
CONFIG_IP_VS_RR=m
CONFIG_SECURITY_SELINUX=y
CONFIG_SECURITY_APPARMOR=y
CONFIG_EXT4_FS=y
CONFIG_EXT4_FS_POSIX_ACL=y
CONFIG_EXT4_FS_SECURITY=y
CONFIG_VXLAN=m
CONFIG_BRIDGE_VLAN_FILTERING=y
CONFIG_CRYPTO=y
CONFIG_CRYPTO_AEAD=y
CONFIG_CRYPTO_GCM=y
CONFIG_CRYPTO_SEQIV=y
CONFIG_CRYPTO_GHASH=y
CONFIG_XFRM=y
CONFIG_XFRM_USER=m
CONFIG_XFRM_ALGO=m
CONFIG_INET_ESP=m
CONFIG_NETFILTER_XT_MATCH_BPF=m
CONFIG_IPVLAN=m
CONFIG_MACVLAN=m
CONFIG_DUMMY=m
CONFIG_NF_NAT_FTP=m
CONFIG_NF_CONNTRACK_FTP=m
CONFIG_NF_NAT_TFTP=m
CONFIG_NF_CONNTRACK_TFTP=m
CONFIG_BTRFS_FS=m
CONFIG_BTRFS_FS_POSIX_ACL=y
CONFIG_OVERLAY_FS=m
CONFIG_IPV6=y
CONFIG_IP_NF_IPTABLES=m
CONFIG_IP_VS=m
CONFIG_NETFILTER=y
CONFIG_NETFILTER_XTABLES=m
CONFIG_NFT_COMPAT=m
CONFIG_NFT_NAT=m
CONFIG_NF_CONNTRACK=m
CONFIG_NF_TABLES=m
CONFIG_NF_TABLES_INET=y
CONFIG_ENA_ETHERNET=m
CONFIG_BLK_DEV_NVME=y
CONFIG_TEST_VMALLOC=m
CONFIG_XFS_FS=m
CONFIG_BNXT=m
CONFIG_DCB=y
CONFIG_BNXT_DCB=y
CONFIG_INFINIBAND=m
CONFIG_INFINIBAND_USER_ACCESS=m
CONFIG_INFINIBAND_BNXT_RE=m
CONFIG_RDMA_RXE=m
CONFIG_MD_RAID0=m
CONFIG_NETCONSOLE=m
FASTPATH
}

install_packages() {
  log "Updating apt metadata"
  sudo apt-get update -y
  log "Upgrading packages"
  sudo DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y

  local packages=(
    socat python3-pip python3-venv git bc rsync dwarves build-essential
    libncurses5-dev bison flex libssl-dev libelf-dev debhelper-compat
    pkg-config libtraceevent-dev libtracefs-dev libdw-dev systemtap-sdt-dev
    libunwind-dev libslang2-dev libperl-dev libcapstone-dev libnuma-dev
    libcap-dev libpci-dev libbabeltrace-dev libpfm4-dev libbfd-dev python3-dev
    liblzma-dev docker.io pipx gettext llvm-dev lsb-release
  )

  log "Installing kernel build dependencies"
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages[@]}"
}

ensure_virtualenv() {
  require_cmd python3
  if [[ ! -d "${VENV_PATH}" ]]; then
    log "Creating tuxmake virtualenv at ${VENV_PATH}"
    python3 -m venv "${VENV_PATH}"
  fi
  # shellcheck source=/dev/null
  source "${VENV_PATH}/bin/activate"
  pip install --upgrade pip >/dev/null
  pip install --upgrade tuxmake >/dev/null
  deactivate
}

clone_kernel_repo() {
  log "Cloning kernel repo into ${KERNEL_DIR}"
  rm -rf "${KERNEL_DIR}"
  mkdir -p "$(dirname "${KERNEL_DIR}")"
  git config --global --add safe.directory "${KERNEL_DIR}" >/dev/null 2>&1 || true
  if [[ -n "${TAG}" ]]; then
    git clone --depth 1 --branch "${TAG}" "${REPO}" "${KERNEL_DIR}"
  elif [[ -n "${BRANCH}" ]]; then
    git clone --depth 1 --branch "${BRANCH}" "${REPO}" "${KERNEL_DIR}"
  else
    git clone --depth 1 "${REPO}" "${KERNEL_DIR}"
  fi
}

prepare_kernel_tree() {
  log "Cleaning kernel tree"
  pushd "${KERNEL_DIR}" >/dev/null
  make mrproper
  popd >/dev/null
}

stage_base_config() {
  local base_config="/tmp/kernel_base.config"
  if [[ -n "${CONFIG_FILE}" ]]; then
    cp "${CONFIG_FILE}" "${base_config}"
  else
    cp "/boot/config-$(uname -r)" "${base_config}"
  fi
  echo "${base_config}"
}

write_custom_configs() {
  local file="/tmp/kernel_customizations.config"
  : >"${file}"
  cat >>"${file}" <<'BASE'
CONFIG_SYSTEM_TRUSTED_KEYS=""
CONFIG_SYSTEM_REVOCATION_KEYS=""
BASE
  if [[ "${FASTPATH}" == "true" ]]; then
    append_fastpath_configs "${file}"
  fi
  if [[ "${CHANGE_TO_64K}" == "true" ]]; then
    cat >>"${file}" <<'PAGES'
CONFIG_ARM64_64K_PAGES=y
CONFIG_ARM64_4K_PAGES=n
PAGES
  fi
  if [[ -n "${TAG}" ]]; then
    local numeric_tag="${TAG#v}"
    if version_in_range "${numeric_tag}" "6.6" "6.7"; then
      cat >>"${file}" <<'ZSTD'
CONFIG_MODULE_COMPRESS_ZSTD=n
ZSTD
    fi
  fi
  echo "${file}"
}

update_extraversion() {
  local os_name
  os_name="$(lsb_release -si 2>/dev/null | tr '[:upper:]' '[:lower:]' || true)"
  if [[ -z "${os_name}" ]]; then
    os_name="$(uname -s | tr '[:upper:]' '[:lower:]')"
  fi
  local suffix="${APPEND_TO_KERNEL_VERSION}"
  local extra="-${os_name}${suffix}"
  if [[ "${CHANGE_TO_64K}" == "true" ]]; then
    extra="-${os_name}-64k${suffix}"
  fi
  sed -i "s/^EXTRAVERSION = .*/EXTRAVERSION = ${extra}/" "${KERNEL_DIR}/Makefile"
}

collect_kernel_info() {
  pushd "${KERNEL_DIR}" >/dev/null
  local kernel_version
  kernel_version="$(make kernelversion | tr -d '[:space:]')"
  popd >/dev/null
  echo "${kernel_version}"
}

run_tuxmake_build() {
  local base_config="$1"
  local custom_config="$2"
  local output_dir="$3"
  mkdir -p "${output_dir}"
  log "Starting tuxmake build (this can take a while)"
  # shellcheck source=/dev/null
  source "${VENV_PATH}/bin/activate"
  pushd "${KERNEL_DIR}" >/dev/null
  tuxmake \
    --output-dir "${output_dir}" \
    --jobs "$(nproc)" \
    --runtime=null \
    --kconfig="${base_config}" \
    --kconfig-add="${custom_config}" \
    kernel modules perf cpupower bindeb-pkg
  popd >/dev/null
  deactivate
}

install_kernel_artifacts() {
  local output_dir="$1"
  local kernel_version="$2"
  log "Installing kernel artifacts"
  sudo cp "${output_dir}/config" "/boot/config-${kernel_version}"
  sudo cp "${output_dir}/Image.gz" "/boot/vmlinuz-${kernel_version}"
  sudo rm -rf "/lib/modules/${kernel_version}"
  sudo tar -C / -xf "${output_dir}/modules.tar.xz" --strip-components=2
  sudo tar -C /usr/bin -xf "${output_dir}/perf.tar.xz" --strip-components=3 ./usr/bin/perf ./usr/bin/trace
  sudo tar -C /usr/bin -xf "${output_dir}/cpupower.tar.xz" --strip-components=3 ./usr/bin/cpupower
  sudo tar -C /usr/lib -xf "${output_dir}/cpupower.tar.xz" --strip-components=3 --wildcards ./usr/lib/libcpupower.so*
  sudo ldconfig

  if [[ -n "${KERNEL_CMDLINE}" ]]; then
    sudo sed -i "s/^GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX=\"${KERNEL_CMDLINE}\"/" /etc/default/grub
  fi
  sudo update-grub || true
}

prompt_reboot() {
  read -rp "Kernel installed. Reboot now? (y/N): " reboot_resp
  if [[ "${reboot_resp,,}" =~ ^(y|yes)$ ]]; then
    log "Rebooting..."
    sudo reboot
  else
    log "Reboot skipped. Remember to reboot manually to use the new kernel."
  fi
}

summarize_settings() {
  cat <<SUMMARY
Kernel build settings:
  Repo:                ${REPO}
  Branch:              ${BRANCH}
  Tag:                 ${TAG}
  Config file:         ${CONFIG_FILE:-/boot/config-$(uname -r)}
  Kernel dir:          ${KERNEL_DIR}
  Output base:         ${OUTPUT_BASE}
  Fastpath configs:    ${FASTPATH}
  64K page size:       ${CHANGE_TO_64K}
  Kernel install:      ${KERNEL_INSTALL}
  Kernel cmdline:      ${KERNEL_CMDLINE:-<unchanged>}
  Append to version:   ${APPEND_TO_KERNEL_VERSION:-<none>}
  Tuxmake virtualenv:  ${VENV_PATH}
SUMMARY
}

main() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --repo) REPO="$2"; shift 2 ;;
      --branch) BRANCH="$2"; shift 2 ;;
      --tag) TAG="$2"; shift 2 ;;
      --tag-latest) TAG=""; shift 1 ;;
      --config-file) CONFIG_FILE="$2"; shift 2 ;;
      --kernel-command-line) KERNEL_CMDLINE="$2"; shift 2 ;;
      --append-to-kernel-version|--append) APPEND_TO_KERNEL_VERSION="$2"; shift 2 ;;
      --kernel-install) KERNEL_INSTALL="$(parse_bool "$2")"; shift 2 ;;
      --change-to-64k) CHANGE_TO_64K="$(parse_bool "$2")"; shift 2 ;;
      --fastpath) FASTPATH="$(parse_bool "$2")"; shift 2 ;;
      --kernel-dir) KERNEL_DIR="$2"; shift 2 ;;
      --output-base) OUTPUT_BASE="$2"; shift 2 ;;
      --venv-path) VENV_PATH="$2"; shift 2 ;;
      --assume-yes) ASSUME_YES="true"; shift 1 ;;
      -h|--help) usage; exit 0 ;;
      *) fail "Unknown argument: $1" ;;
    esac
  done

  [[ -n "${REPO}" ]] || fail "Kernel repo (--repo) cannot be empty"
  if [[ -n "${CONFIG_FILE}" && ! -f "${CONFIG_FILE}" ]]; then
    fail "Config file ${CONFIG_FILE} does not exist"
  fi

  summarize_settings
  if [[ "${ASSUME_YES}" != "true" ]]; then
    read -rp "Proceed with kernel build? (y/N): " resp
    [[ "${resp,,}" =~ ^(y|yes)$ ]] || { log "Aborted by user"; exit 0; }
  fi

  require_cmd sudo
  require_cmd git
  require_cmd dpkg

  install_packages
  ensure_virtualenv
  clone_kernel_repo
  prepare_kernel_tree

  local base_config custom_config
  base_config="$(stage_base_config)"
  custom_config="$(write_custom_configs)"
  update_extraversion

  local uname_current os_name page_size
  uname_current="$(uname -r)"
  os_name="$(lsb_release -si 2>/dev/null || uname -s)"
  page_size="$(getconf PAGE_SIZE)"

  local kernel_version
  kernel_version="$(collect_kernel_info)"
  local output_dir="${OUTPUT_BASE}/${kernel_version}"
  rm -rf "${output_dir}/build"

  cat <<INFO
Host information:
  OS:                  ${os_name}
  Current kernel:      ${uname_current}
  Current page size:   ${page_size}
  Building version:    ${kernel_version}
  Output directory:    ${output_dir}
INFO

  run_tuxmake_build "${base_config}" "${custom_config}" "${output_dir}"

  log "Build artifacts are located in ${output_dir}"

  if [[ "${KERNEL_INSTALL}" == "true" ]]; then
    install_kernel_artifacts "${output_dir}" "${kernel_version}"
    prompt_reboot
  else
    log "Kernel install disabled; skipping artifact installation."
  fi
}

main "$@"
