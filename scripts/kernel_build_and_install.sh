#!/usr/bin/env bash
set -euo pipefail

# shellcheck disable=SC2034
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_PATH="${SCRIPT_DIR}/$(basename "${BASH_SOURCE[0]}")"

KERNEL_REPO="git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git"
KERNEL_BRANCH="linux-rolling-stable"
TAG_DEFAULT=""
CONFIG_FILE_DEFAULT=""
KERNEL_CMDLINE_DEFAULT=""
APPEND_TO_KERNEL_VERSION_DEFAULT=""
KERNEL_INSTALL_DEFAULT="false"
CHANGE_TO_64K_DEFAULT="false"
FASTPATH_DEFAULT="false"
KERNEL_DIR_DEFAULT="${HOME}/kernels/linux"
OUTPUT_BASE_DEFAULT="${HOME}/kernels"
VENV_PATH_DEFAULT="${HOME}/venv-tuxmake"
INCLUDE_BINDEB_PKG_DEFAULT="false"
DEMO_FASTPATH_BUILDS_DEFAULT="false"
DEMO_DEFAULT_BUILD_DEFAULT="false"
REQUIRES_DOCKER_DEFAULT="false"
INSTALL_FORMAT_DEFAULT="auto"
DRY_RUN_DEFAULT="false"

CONFIG_FILE="${CONFIG_FILE_DEFAULT}"
KERNEL_CMDLINE="${KERNEL_CMDLINE_DEFAULT}"
APPEND_TO_KERNEL_VERSION="${APPEND_TO_KERNEL_VERSION_DEFAULT}"
KERNEL_INSTALL="${KERNEL_INSTALL_DEFAULT}"
KERNEL_INSTALL_OPTIONAL_TAG=""
KERNEL_INSTALL_TARGET=""
CHANGE_TO_64K="${CHANGE_TO_64K_DEFAULT}"
FASTPATH="${FASTPATH_DEFAULT}"
KERNEL_DIR="${KERNEL_DIR_DEFAULT}"
OUTPUT_BASE="${OUTPUT_BASE_DEFAULT}"
VENV_PATH="${VENV_PATH_DEFAULT}"
INCLUDE_BINDEB_PKG="${INCLUDE_BINDEB_PKG_DEFAULT}"
DEMO_FASTPATH_BUILDS="${DEMO_FASTPATH_BUILDS_DEFAULT}"
DEMO_DEFAULT_BUILD="${DEMO_DEFAULT_BUILD_DEFAULT}"
REQUIRES_DOCKER="${REQUIRES_DOCKER_DEFAULT}"
INSTALL_FROM_PATH=""
INSTALL_FORMAT="${INSTALL_FORMAT_DEFAULT}"
DRY_RUN="${DRY_RUN_DEFAULT}"
PLAN_FILE_PATH=""
declare -a FORWARDED_ARGS=()
declare -a TAGS=()
TOTAL_BUILDS=0

usage() {
  cat <<'USAGE'
Usage: kernel_build_and_install.sh [options]

Options:
  --tag <tag>                      Kernel tag to checkout (can be repeated)
  --tags <tag1,tag2>               Comma-separated list of tags to build
  --tag-latest                     Add the latest stable kernel (empty tag)
  --config-file <path>             Custom base config instead of current kernel config
  --kernel-command-line <string>   Override GRUB kernel command line on install
  --append-to-kernel-version <str> Text appended to EXTRAVERSION
  --append <str>                   Alias for --append-to-kernel-version
  --kernel-dir <path>              Base directory for kernel repo (default: ~/kernels/linux)
  --kernel-install [tag|bool]      Install kernel (multi-tag requires tag name)
  --change-to-64k <bool>           Enable 64K page size (default: false)
  --fastpath <bool>                Apply fastpath configs (default: false)
  --venv-path <path>               Python venv for tuxmake (default: ~/venv-tuxmake)
  --include-bindeb-pkg             Add bindeb-pkg target to the tuxmake run (default: omit)
  --install-from <dir>              Install an existing kernel from artifacts in <dir>
  --install-format <flat|deb|auto>  Force interpretation of --install-from artifacts (default: auto)
  --dry-run                         Generate a runnable plan script (minus --dry-run) and exit
  --demo-default-build             Shortcut for --tags v6.18.1 --fastpath false
  --demo-fastpath-build            Shortcut for --tags v6.18.1,v6.19-rc1 --fastpath true
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
    liblzma-dev pipx gettext llvm-dev lsb-release initramfs-tools
  )

  if [[ "${REQUIRES_DOCKER}" == "true" ]]; then
    packages+=("docker.io")
  fi

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
  local repo="$1"
  local branch="$2"
  local tag="$3"
  local dest="$4"
  log "Cloning kernel repo into ${dest}"
  rm -rf "${dest}"
  mkdir -p "$(dirname "${dest}")"
  git config --global --add safe.directory "${dest}" >/dev/null 2>&1 || true
  if [[ -n "${tag}" ]]; then
    git clone --depth 1 --branch "${tag}" "${repo}" "${dest}"
  elif [[ -n "${branch}" ]]; then
    git clone --depth 1 --branch "${branch}" "${repo}" "${dest}"
  else
    git clone --depth 1 "${repo}" "${dest}"
  fi
}

prepare_kernel_tree() {
  local kernel_dir="$1"
  log "Cleaning kernel tree at ${kernel_dir}"
  pushd "${kernel_dir}" >/dev/null
  make mrproper
  popd >/dev/null
}

resolve_base_config_source() {
  if [[ -n "${CONFIG_FILE}" ]]; then
    echo "${CONFIG_FILE}"
  else
    local default="/boot/config-$(uname -r)"
    [[ -f "${default}" ]] || fail "Default config ${default} not found; specify --config-file"
    echo "${default}"
  fi
}

stage_base_config() {
  local dest="$1"
  local source_config="$2"
  if [[ -e "${dest}" && -e "${source_config}" && "${source_config}" -ef "${dest}" ]]; then
    return
  fi
  cp "${source_config}" "${dest}"
}

preserve_source_config() {
  local source_config="$1"
  local output_dir="$2"
  local host_kernel="$3"
  local stock_dir="${OUTPUT_BASE}/stock-configs"
  mkdir -p "${output_dir}" "${stock_dir}"
  cp -f "${source_config}" "${output_dir}/config.stock"
  local sanitized_kernel="${host_kernel//\//-}"
  local stock_target="${stock_dir}/config-${sanitized_kernel}"
  if [[ -e "${stock_target}" && "${source_config}" -ef "${stock_target}" ]]; then
    :
  else
    cp -f "${source_config}" "${stock_target}"
  fi
}

write_custom_configs() {
  local file="$1"
  local fastpath="$2"
  local change_to_64k="$3"
  local tag="$4"
  : >"${file}"
  cat >>"${file}" <<'BASE'
CONFIG_SYSTEM_TRUSTED_KEYS=""
CONFIG_SYSTEM_REVOCATION_KEYS=""
BASE
  if [[ "${fastpath}" == "true" ]]; then
    append_fastpath_configs "${file}"
  fi
  if [[ "${change_to_64k}" == "true" ]]; then
    cat >>"${file}" <<'PAGES'
CONFIG_ARM64_64K_PAGES=y
CONFIG_ARM64_4K_PAGES=n
PAGES
  fi
  if [[ -n "${tag}" ]]; then
    local numeric_tag="${tag#v}"
    if version_in_range "${numeric_tag}" "6.6" "6.7"; then
      cat >>"${file}" <<'ZSTD'
CONFIG_MODULE_COMPRESS_ZSTD=n
ZSTD
    fi
  fi
}

update_extraversion() {
  local kernel_dir="$1"
  local change_to_64k="$2"
  local append_value="$3"
  local original_line original_extraversion
  original_line="$(grep -m1 '^EXTRAVERSION[[:space:]]*=' "${kernel_dir}/Makefile" || true)"
  original_extraversion="${original_line#*=}"
  original_extraversion="$(echo "${original_extraversion}" | sed -e 's/^[[:space:]]*//')"
  local os_name
  os_name="$(lsb_release -si 2>/dev/null | tr '[:upper:]' '[:lower:]' || uname -s | tr '[:upper:]' '[:lower:]')"
  local extra_suffix="-${os_name}${append_value}"
  if [[ "${change_to_64k}" == "true" ]]; then
    extra_suffix="-${os_name}-64k${append_value}"
  fi
  local new_extraversion
  if [[ -n "${original_extraversion}" ]]; then
    new_extraversion="${original_extraversion}${extra_suffix}"
  else
    new_extraversion="${extra_suffix}"
  fi
  sed -i "s/^EXTRAVERSION[[:space:]]*=.*/EXTRAVERSION = ${new_extraversion}/" "${kernel_dir}/Makefile"
}

collect_kernel_info() {
  local kernel_dir="$1"
  pushd "${kernel_dir}" >/dev/null
  local kernel_version
  kernel_version="$(make kernelversion | tr -d '[:space:]')"
  popd >/dev/null
  echo "${kernel_version}"
}

detect_artifact_kernel_release() {
  local artifact_dir="$1"
  local fallback="$2"
  local metadata_file="${artifact_dir}/metadata.json"
  if [[ -f "${metadata_file}" ]]; then
    local release=""
    release="$(python3 - "${metadata_file}" <<'PY'
import json, sys
path = sys.argv[1]
with open(path) as fh:
    data = json.load(fh)
print(data.get("source", {}).get("kernelrelease", ""))
PY
)" || release=""
    if [[ -n "${release}" ]]; then
      echo "${release}"
      return
    fi
  fi
  local tarball="${artifact_dir}/modules.tar.xz"
  if [[ -f "${tarball}" ]]; then
    local version=""
    version="$(tar -tf "${tarball}" 2>/dev/null | awk -F'/' '$1 == "lib" && $2 == "modules" && $3 != "" {print $3; exit}')" || version=""
    if [[ -n "${version}" ]]; then
      echo "${version}"
      return
    fi
  fi
  echo "${fallback}"
}

determine_built_kernel_release() {
  local kernel_dir="$1"
  local build_dir="$2"
  local fallback="$3"
  local output_dir="${4-}"
  local release=""
  local release_file="${build_dir}/include/config/kernel.release"
  if [[ -f "${release_file}" ]]; then
    release="$(tr -d '[:space:]' <"${release_file}")"
    if [[ -n "${release}" ]]; then
      echo "${release}"
      return
    fi
  fi
  if [[ -z "${release}" && -n "${output_dir}" ]]; then
    release="$(detect_artifact_kernel_release "${output_dir}" "")"
    if [[ -n "${release}" ]]; then
      echo "${release}"
      return
    fi
  fi
  if [[ -d "${kernel_dir}" ]]; then
    pushd "${kernel_dir}" >/dev/null
    release="$(make -s O="${build_dir}" kernelrelease 2>/dev/null | tr -d '[:space:]')" || release=""
    popd >/dev/null
  fi
  if [[ -n "${release}" ]]; then
    echo "${release}"
  else
    echo "${fallback}"
  fi
}

run_tuxmake_build() {
  local kernel_dir="$1"
  local base_config="$2"
  local custom_config="$3"
  local output_dir="$4"
  local venv_path="$5"
  mkdir -p "${output_dir}"
  log "Building kernel in ${kernel_dir} (output -> ${output_dir})"
  local -a targets=(kernel modules perf cpupower)
  if [[ "${INCLUDE_BINDEB_PKG}" == "true" ]]; then
    targets+=(bindeb-pkg)
  fi
  # shellcheck source=/dev/null
  source "${venv_path}/bin/activate"
  pushd "${kernel_dir}" >/dev/null
  tuxmake \
    --output-dir "${output_dir}" \
    --jobs "$(nproc)" \
    --runtime=null \
    --kconfig="${base_config}" \
    --kconfig-add="${custom_config}" \
    "${targets[@]}"
  popd >/dev/null
  deactivate
}

save_kernel_metadata() {
  local output_dir="$1"
  local kernel_version="$2"
  printf '%s\n' "${kernel_version}" > "${output_dir}/.kernel-version"
}

read_kernel_version_from_dir() {
  local dir="$1"
  if [[ -f "${dir}/.kernel-version" ]]; then
    local stored
    stored="$(<"${dir}/.kernel-version")"
    if [[ -n "${stored}" ]]; then
      echo "${stored}"
      return
    fi
  fi
  if [[ -f "${dir}/config" ]]; then
    local from_config
    from_config="$(awk '/^# Linux/ {print $3; exit}' "${dir}/config" | tr -d '[:space:]')" || true
    if [[ -n "${from_config}" ]]; then
      echo "${from_config}"
      return
    fi
  fi
  basename "${dir}"
}

detect_install_format() {
  local dir="$1"
  local preferred="$2"
  local fmt="${preferred,,}"
  case "${fmt}" in
    flat|deb)
      echo "${fmt}"
      ;;
    auto)
      if find "${dir}" -maxdepth 1 -type f -name '*.deb' -print -quit | grep -q .; then
        echo "deb"
        return
      fi
      if [[ -f "${dir}/Image.gz" && -f "${dir}/modules.tar.xz" ]]; then
        echo "flat"
        return
      fi
      fail "Could not auto-detect artifact format inside ${dir}"
      ;;
    *)
      fail "Unknown install format '${preferred}'. Use flat, deb, or auto."
      ;;
  esac
}

apply_kernel_cmdline() {
  local kernel_cmdline="$1"
  if [[ -n "${kernel_cmdline}" ]]; then
    sudo sed -i "s/^GRUB_CMDLINE_LINUX=.*/GRUB_CMDLINE_LINUX=\"${kernel_cmdline}\"/" /etc/default/grub
  fi
  sudo update-grub || true
}

install_kernel_from_debs() {
  local dir="$1"
  local kernel_cmdline="$2"
  log "Installing kernel from DEB packages in ${dir}"
  local -a debs=()
  while IFS= read -r -d '' deb; do
    debs+=("$deb")
  done < <(find "${dir}" -maxdepth 1 -type f -name '*.deb' -print0 | LC_ALL=C sort -z)
  (( ${#debs[@]} > 0 )) || fail "No .deb packages found in ${dir}"
  sudo dpkg -i "${debs[@]}"
  apply_kernel_cmdline "${kernel_cmdline}"
}

detect_kernel_version_from_debs() {
  local dir="$1"
  local fallback="$2"
  local image_deb
  image_deb="$(find "${dir}" -maxdepth 1 -type f -name 'linux-image-*.deb' | LC_ALL=C sort | head -n1 || true)"
  if [[ -n "${image_deb}" ]]; then
    local base
    base="$(basename "${image_deb}")"
    base="${base#linux-image-}"
    base="${base%%_*}"
    echo "${base}"
    return
  fi
  echo "${fallback}"
}

install_prebuilt_kernel() {
  local source_dir="$1"
  local preferred_format="$2"
  local kernel_cmdline="$3"
  [[ -d "${source_dir}" ]] || fail "Install source ${source_dir} does not exist"

  local format
  format="$(detect_install_format "${source_dir}" "${preferred_format}")"
  local kernel_version
  kernel_version="$(read_kernel_version_from_dir "${source_dir}")"
  [[ -n "${kernel_version}" ]] || fail "Unable to determine kernel version from ${source_dir}"

  case "${format}" in
    flat)
      [[ -f "${source_dir}/Image.gz" ]] || fail "Missing Image.gz in ${source_dir}"
      [[ -f "${source_dir}/modules.tar.xz" ]] || fail "Missing modules.tar.xz in ${source_dir}"
      [[ -f "${source_dir}/config" ]] || fail "Missing config in ${source_dir}"
      install_kernel_artifacts "${source_dir}" "${kernel_version}" "${kernel_cmdline}"
      ;;
    deb)
      kernel_version="$(detect_kernel_version_from_debs "${source_dir}" "${kernel_version}")"
      install_kernel_from_debs "${source_dir}" "${kernel_cmdline}"
      ;;
  esac

  log "Kernel ${kernel_version} installation complete"
  prompt_reboot
}

install_kernel_artifacts() {
  local output_dir="$1"
  local kernel_version="$2"
  local kernel_cmdline="$3"
  local modules_tar="${output_dir}/modules.tar.xz"
  kernel_version="$(detect_artifact_kernel_release "${output_dir}" "${kernel_version}")"
  log "Installing kernel artifacts from ${output_dir} (release ${kernel_version})"
  sudo cp "${output_dir}/config" "/boot/config-${kernel_version}"
  sudo cp "${output_dir}/Image.gz" "/boot/vmlinuz-${kernel_version}"
  sudo rm -rf "/lib/modules/${kernel_version}"
  sudo tar -C /lib -xf "${modules_tar}" --strip-components=1
  sudo depmod "${kernel_version}"
  if [[ -f "${output_dir}/perf.tar.xz" ]]; then
    sudo tar -C /usr/bin -xf "${output_dir}/perf.tar.xz" --strip-components=3 ./usr/bin/perf ./usr/bin/trace
  fi
  if [[ -f "${output_dir}/cpupower.tar.xz" ]]; then
    sudo tar -C /usr/bin -xf "${output_dir}/cpupower.tar.xz" --strip-components=3 ./usr/bin/cpupower
    sudo tar -C /usr/lib -xf "${output_dir}/cpupower.tar.xz" --strip-components=3 --wildcards ./usr/lib/libcpupower.so*
  fi
  sudo ldconfig
  log "Generating initramfs for ${kernel_version}"
  sudo update-initramfs -c -k "${kernel_version}"
  [[ -f "/boot/initrd.img-${kernel_version}" ]] || fail "Initramfs /boot/initrd.img-${kernel_version} was not created"
  apply_kernel_cmdline "${kernel_cmdline}"
}

prompt_reboot() {
  log "Kernel installed. Rebooting immediately."
  sudo reboot
}

update_forwarded_arg() {
  local flag="$1"
  local value="$2"
  for (( i=0; i<${#FORWARDED_ARGS[@]}-1; i++ )); do
    if [[ "${FORWARDED_ARGS[i]}" == "${flag}" ]]; then
      FORWARDED_ARGS[i+1]="${value}"
      return
    fi
  done
}

generate_plan_script() {
  local plan_args=("$@")
  require_cmd python3
  local label_source="${plan_args[*]}"
  local sanitized
  if [[ -z "${label_source}" ]]; then
    sanitized="defaults"
  else
    sanitized="$(printf '%s' "${label_source}" | tr ' ' '_' | tr -cd '[:alnum:]_-')"
    [[ -n "${sanitized}" ]] || sanitized="defaults"
    sanitized="${sanitized:0:48}"
  fi
  local hash
  hash="$(printf '%s\n' "${plan_args[@]}" | python3 - <<'PY'
import hashlib, sys
data = sys.stdin.read().encode()
if not data:
    data = b'defaults'
print(hashlib.sha256(data).hexdigest()[:10])
PY
)"
  local tmp_dir="${TMPDIR:-/tmp}"
  local file_name="kernel_plan_${sanitized}_${hash}.sh"
  PLAN_FILE_PATH="${tmp_dir}/${file_name}"
  {
    head -n 1 "${SCRIPT_PATH}"
    echo "# Generated by kernel_build_and_install.sh --dry-run on $(date -u)"
    tail -n +2 "${SCRIPT_PATH}" | sed '$d'
    printf '\nmain'
    if (( ${#plan_args[@]} > 0 )); then
      printf ' %q' "${plan_args[@]}"
    fi
    echo
  } > "${PLAN_FILE_PATH}"
  chmod +x "${PLAN_FILE_PATH}"
  log "Dry-run plan written to ${PLAN_FILE_PATH}"
  printf '%s\n' "${PLAN_FILE_PATH}"
}

describe_tag() {
  local tag="$1"
  if [[ -n "${tag}" ]]; then
    echo "${tag}"
  else
    echo "<latest-stable>"
  fi
}

build_label() {
  local tag="$1"
  local index="$2"
  local label="${tag:-latest}"
  label="${label//[^[:alnum:]._-]/-}"
  if [[ -z "${label}" ]]; then
    label="build-${index}"
  else
    label="${label}-${index}"
  fi
  echo "${label}"
}

determine_kernel_dir() {
  local label="$1"
  if (( TOTAL_BUILDS <= 1 )); then
    echo "${KERNEL_DIR}"
  else
    echo "${KERNEL_DIR}-${label}"
  fi
}

summarize_settings() {
  local formatted_tags=()
  if (( ${#TAGS[@]} == 0 )); then
    formatted_tags+=("$(describe_tag "")")
  else
    for tag in "${TAGS[@]}"; do
      formatted_tags+=("$(describe_tag "${tag}")")
    done
  fi
  local tag_summary="$(IFS=','; echo "${formatted_tags[*]}")"
  cat <<EOF
Kernel build settings:
  Repo:                ${KERNEL_REPO}
  Branch:              ${KERNEL_BRANCH}
  Tags:                ${tag_summary}
  Config file:         ${CONFIG_FILE:-/boot/config-$(uname -r)}
  Kernel dir base:     ${KERNEL_DIR}
  Output base:         ${OUTPUT_BASE}
  Fastpath configs:    ${FASTPATH}
  64K page size:       ${CHANGE_TO_64K}
  Kernel install:      ${KERNEL_INSTALL}
  Install target:      ${KERNEL_INSTALL_TARGET:-<none>}
  Kernel cmdline:      ${KERNEL_CMDLINE:-<unchanged>}
  Append to version:   ${APPEND_TO_KERNEL_VERSION:-<none>}
  Tuxmake virtualenv:  ${VENV_PATH}
  bindeb-pkg target:   ${INCLUDE_BINDEB_PKG}
EOF
}

summarize_install_from() {
  cat <<EOF
Prebuilt kernel install settings:
  Source directory:   ${INSTALL_FROM_PATH}
  Artifact format:    ${INSTALL_FORMAT}
  Kernel cmdline:     ${KERNEL_CMDLINE:-<unchanged>}
EOF
}

build_kernel_for_tag() {
  local tag="$1"
  local label="$2"
  local host_kernel="$3"
  local os_name="$4"
  local page_size="$5"
  local tag_display
  tag_display="$(describe_tag "${tag}")"
  local kernel_dir
  kernel_dir="$(determine_kernel_dir "${label}")"
  local workspace
  workspace="$(mktemp -d -t kernel-build-XXXXXX)"
  trap "rm -rf '$workspace'" RETURN
  local base_config="${workspace}/kernel_base.config"
  local custom_config="${workspace}/kernel_customizations.config"
  local base_config_source
  base_config_source="$(resolve_base_config_source)"

  log "[${label}] Preparing build for tag ${tag_display}"
  clone_kernel_repo "${KERNEL_REPO}" "${KERNEL_BRANCH}" "${tag}" "${kernel_dir}"
  prepare_kernel_tree "${kernel_dir}"
  stage_base_config "${base_config}" "${base_config_source}"
  write_custom_configs "${custom_config}" "${FASTPATH}" "${CHANGE_TO_64K}" "${tag}"
  update_extraversion "${kernel_dir}" "${CHANGE_TO_64K}" "${APPEND_TO_KERNEL_VERSION}"

  local kernel_version
  kernel_version="$(collect_kernel_info "${kernel_dir}")"
  local output_dir="${OUTPUT_BASE}/${kernel_version}"
  preserve_source_config "${base_config_source}" "${output_dir}" "${host_kernel}"
  rm -rf "${output_dir}/build"

  log "[${label}] Host OS: ${os_name} | Running kernel: ${host_kernel} | Page size: ${page_size}"
  log "[${label}] Building kernel ${kernel_version} -> ${output_dir}"

  run_tuxmake_build "${kernel_dir}" "${base_config}" "${custom_config}" "${output_dir}" "${VENV_PATH}"

  local built_kernel_version
  built_kernel_version="$(determine_built_kernel_release "${kernel_dir}" "${output_dir}/build" "${kernel_version}" "${output_dir}")"
  if [[ "${built_kernel_version}" != "${kernel_version}" ]]; then
    local new_output_dir="${OUTPUT_BASE}/${built_kernel_version}"
    [[ -e "${new_output_dir}" ]] && fail "Output directory ${new_output_dir} already exists; remove it before re-running"
    mv "${output_dir}" "${new_output_dir}"
    output_dir="${new_output_dir}"
  fi
  kernel_version="${built_kernel_version}"

  save_kernel_metadata "${output_dir}" "${kernel_version}"
  log "[${label}] Build artifacts are located in ${output_dir}"

  local install_this_tag="false"
  if [[ "${KERNEL_INSTALL}" == "true" && "${tag}" == "${KERNEL_INSTALL_TARGET}" ]]; then
    install_this_tag="true"
  fi

  if [[ "${install_this_tag}" == "true" ]]; then
    install_kernel_artifacts "${output_dir}" "${kernel_version}" "${KERNEL_CMDLINE}"
    prompt_reboot
  fi
}

main() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --tag)
        TAGS+=("$2")
        FORWARDED_ARGS+=("--tag" "$2")
        shift 2
        ;;
      --tags)
        IFS=',' read -r -a tag_list <<<"$2"
        TAGS+=("${tag_list[@]}")
        FORWARDED_ARGS+=("--tags" "$2")
        shift 2
        ;;
      --tag-latest)
        TAGS+=("")
        FORWARDED_ARGS+=("--tag-latest")
        shift 1
        ;;
      --config-file)
        CONFIG_FILE="$2"
        FORWARDED_ARGS+=("--config-file" "$2")
        shift 2
        ;;
      --kernel-command-line)
        KERNEL_CMDLINE="$2"
        FORWARDED_ARGS+=("--kernel-command-line" "$2")
        shift 2
        ;;
      --append-to-kernel-version|--append)
        APPEND_TO_KERNEL_VERSION="$2"
        FORWARDED_ARGS+=("$1" "$2")
        shift 2
        ;;
      --kernel-install)
        local forwarded_value=""
        next_kernel_install_arg="${2-}"
        if [[ $# -gt 1 && "${next_kernel_install_arg}" != --* ]]; then
          case "${next_kernel_install_arg,,}" in
            y|yes|true|1)
              KERNEL_INSTALL="true"
              KERNEL_INSTALL_OPTIONAL_TAG=""
              forwarded_value="true"
              shift 2
              ;;
            n|no|false|0)
              KERNEL_INSTALL="false"
              KERNEL_INSTALL_OPTIONAL_TAG=""
              forwarded_value="false"
              shift 2
              ;;
            *)
              KERNEL_INSTALL="true"
              KERNEL_INSTALL_OPTIONAL_TAG="${next_kernel_install_arg}"
              forwarded_value="${next_kernel_install_arg}"
              shift 2
              ;;
          esac
        else
          KERNEL_INSTALL="true"
          KERNEL_INSTALL_OPTIONAL_TAG=""
          shift 1
        fi
        if [[ -n "${forwarded_value}" ]]; then
          FORWARDED_ARGS+=("--kernel-install" "${forwarded_value}")
        else
          FORWARDED_ARGS+=("--kernel-install")
        fi
        ;;
      --change-to-64k)
        CHANGE_TO_64K="$(parse_bool "$2")"
        FORWARDED_ARGS+=("--change-to-64k" "${CHANGE_TO_64K}")
        shift 2
        ;;
      --fastpath)
        FASTPATH="$(parse_bool "$2")"
        FORWARDED_ARGS+=("--fastpath" "${FASTPATH}")
        if [[ "${FASTPATH}" == "true" ]]; then
          REQUIRES_DOCKER="true"
        fi
        shift 2
        ;;
      --kernel-dir)
        KERNEL_DIR="$2"
        FORWARDED_ARGS+=("--kernel-dir" "$2")
        shift 2
        ;;
      --venv-path)
        VENV_PATH="$2"
        FORWARDED_ARGS+=("--venv-path" "$2")
        shift 2
        ;;
      --include-bindeb-pkg)
        INCLUDE_BINDEB_PKG="true"
        FORWARDED_ARGS+=("--include-bindeb-pkg")
        shift 1
        ;;
      --install-from)
        INSTALL_FROM_PATH="$2"
        FORWARDED_ARGS+=("--install-from" "$2")
        shift 2
        ;;
      --install-format)
        INSTALL_FORMAT="$2"
        FORWARDED_ARGS+=("--install-format" "$2")
        shift 2
        ;;
      --demo-default-build)
        DEMO_DEFAULT_BUILD="true"
        FORWARDED_ARGS+=("--demo-default-build")
        shift 1
        ;;
      --demo-fastpath-build)
        DEMO_FASTPATH_BUILDS="true"
        FASTPATH="true"
        FORWARDED_ARGS+=("--demo-fastpath-build")
        shift 1
        ;;
      --dry-run)
        DRY_RUN="true"
        shift 1
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *) fail "Unknown argument: $1" ;;
    esac
  done

  if [[ "${DEMO_DEFAULT_BUILD}" == "true" && "${DEMO_FASTPATH_BUILDS}" == "true" ]]; then
    fail "--demo-default-build and --demo-fastpath-build cannot be used together"
  fi

  if [[ "${DEMO_DEFAULT_BUILD}" == "true" ]]; then
    TAGS=("v6.18.1")
    FASTPATH="false"
  fi

  if [[ "${DEMO_FASTPATH_BUILDS}" == "true" ]]; then
    TAGS=("v6.18.1" "v6.19-rc1")
    FASTPATH="true"
  fi

  if [[ "${FASTPATH}" == "true" ]]; then
    REQUIRES_DOCKER="true"
  else
    REQUIRES_DOCKER="false"
  fi

  local INSTALL_FROM_REQUESTED="false"
  if [[ -n "${INSTALL_FROM_PATH}" ]]; then
    if [[ "${KERNEL_INSTALL}" == "true" || -n "${KERNEL_INSTALL_OPTIONAL_TAG}" ]]; then
      fail "--install-from cannot be combined with --kernel-install"
    fi
    INSTALL_FROM_PATH="$(readlink -f "${INSTALL_FROM_PATH}")"
    [[ -d "${INSTALL_FROM_PATH}" ]] || fail "Install source ${INSTALL_FROM_PATH} does not exist"
    update_forwarded_arg "--install-from" "${INSTALL_FROM_PATH}"
    INSTALL_FROM_REQUESTED="true"
  fi

  if (( ${#TAGS[@]} == 0 )); then
    TAGS+=("${TAG_DEFAULT}")
  fi
  TOTAL_BUILDS=${#TAGS[@]}

  if [[ -n "${CONFIG_FILE}" && ! -f "${CONFIG_FILE}" ]]; then
    fail "Config file ${CONFIG_FILE} does not exist"
  fi
  if [[ -n "${CONFIG_FILE}" ]]; then
    CONFIG_FILE="$(readlink -f "${CONFIG_FILE}")"
    update_forwarded_arg "--config-file" "${CONFIG_FILE}"
  fi

  if [[ "${DRY_RUN}" == "true" ]]; then
    generate_plan_script "${FORWARDED_ARGS[@]}"
    exit 0
  fi

  if [[ "${INSTALL_FROM_REQUESTED}" == "true" ]]; then
    summarize_install_from

    require_cmd sudo
    require_cmd dpkg
    require_cmd tar
    install_prebuilt_kernel "${INSTALL_FROM_PATH}" "${INSTALL_FORMAT}" "${KERNEL_CMDLINE}"
    exit 0
  fi
  if [[ "${KERNEL_INSTALL}" == "true" ]]; then
    if (( TOTAL_BUILDS == 1 )); then
      local sole_tag="${TAGS[0]}"
      if [[ -n "${KERNEL_INSTALL_OPTIONAL_TAG}" && "${KERNEL_INSTALL_OPTIONAL_TAG}" != "${sole_tag}" ]]; then
        fail "--kernel-install was set to install '${KERNEL_INSTALL_OPTIONAL_TAG}', but the build only includes '${sole_tag}'"
      fi
      KERNEL_INSTALL_TARGET="${sole_tag}"
    else
      if [[ -z "${KERNEL_INSTALL_OPTIONAL_TAG}" ]]; then
        fail "When building multiple tags, --kernel-install must be followed by one of the requested tags"
      fi
      local match="false"
      for tag in "${TAGS[@]}"; do
        if [[ "${tag}" == "${KERNEL_INSTALL_OPTIONAL_TAG}" ]]; then
          match="true"
          break
        fi
      done
      if [[ "${match}" != "true" ]]; then
        fail "Kernel install target '${KERNEL_INSTALL_OPTIONAL_TAG}' was not included in the --tag/--tags list"
      fi
      KERNEL_INSTALL_TARGET="${KERNEL_INSTALL_OPTIONAL_TAG}"
    fi
  fi

  local -a BUILD_TAGS=("${TAGS[@]}")
  if [[ "${KERNEL_INSTALL}" == "true" && TOTAL_BUILDS > 1 ]]; then
    BUILD_TAGS=()
    for tag in "${TAGS[@]}"; do
      if [[ "${tag}" != "${KERNEL_INSTALL_TARGET}" ]]; then
        BUILD_TAGS+=("${tag}")
      fi
    done
    BUILD_TAGS+=("${KERNEL_INSTALL_TARGET}")
  fi

  summarize_settings

  require_cmd sudo
  require_cmd git
  require_cmd dpkg

  install_packages
  ensure_virtualenv
  mkdir -p "${OUTPUT_BASE}"

  local host_kernel os_name page_size
  host_kernel="$(uname -r)"
  os_name="$(lsb_release -si 2>/dev/null || uname -s)"
  page_size="$(getconf PAGE_SIZE)"

  if (( TOTAL_BUILDS == 1 )) || [[ "${KERNEL_INSTALL}" == "true" ]]; then
    local index=0
    for tag in "${BUILD_TAGS[@]}"; do
      index=$((index + 1))
      local label
      label="$(build_label "${tag}" "${index}")"
      build_kernel_for_tag "${tag}" "${label}" "${host_kernel}" "${os_name}" "${page_size}"
    done
  else
    local -a job_pids=()
    local -a labels=()
    local index=0
    for tag in "${BUILD_TAGS[@]}"; do
      index=$((index + 1))
      local label
      label="$(build_label "${tag}" "${index}")"
      ( build_kernel_for_tag "${tag}" "${label}" "${host_kernel}" "${os_name}" "${page_size}" ) &
      job_pids+=($!)
      labels+=("${label}")
    done
    local rc=0
    for i in "${!job_pids[@]}"; do
      if ! wait "${job_pids[$i]}"; then
        log "Build ${labels[$i]} failed"
        rc=1
      fi
    done
    (( rc == 0 )) || fail "One or more kernel builds failed"
  fi
}

main "$@"
