#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_PATH="${REPO_ROOT}/scripts/kernel_build_and_install.sh"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

call_reader() {
  local kernel_version="$1"
  local grub_cfg="$2"
  bash -c "source '${SCRIPT_PATH}'; find_grub_menuentry_id '${kernel_version}' '${grub_cfg}'"
}

tmp="$(mktemp -d)"
trap "rm -rf '${tmp}'" EXIT

grub_cfg="${tmp}/grub.cfg"
cat >"${grub_cfg}" <<'EOF'
menuentry 'Ubuntu' --class ubuntu --class gnu-linux --class gnu --class os $menuentry_id_option 'gnulinux-simple-uuid' {
}
submenu 'Advanced options for Ubuntu' $menuentry_id_option 'gnulinux-advanced-uuid' {
  menuentry 'Ubuntu, with Linux 6.1.87-ubuntu-64k-64k+' --class ubuntu --class gnu-linux --class gnu --class os $menuentry_id_option 'gnulinux-6.1.87-ubuntu-64k-64k+-advanced-uuid' {
  }
  menuentry 'Ubuntu, with Linux 6.1.87-ubuntu-64k-64k+ (recovery mode)' --class ubuntu --class gnu-linux --class gnu --class os $menuentry_id_option 'gnulinux-6.1.87-ubuntu-64k-64k+-recovery-advanced-uuid' {
  }
  menuentry 'Ubuntu, with Linux 6.1.87-ubuntu-4k+' --class ubuntu --class gnu-linux --class gnu --class os $menuentry_id_option 'gnulinux-6.1.87-ubuntu-4k+-advanced-uuid' {
  }
}
EOF

got_64k="$(call_reader "6.1.87-ubuntu-64k-64k+" "${grub_cfg}")"
[[ "${got_64k}" == "gnulinux-6.1.87-ubuntu-64k-64k+-advanced-uuid" ]] || fail "64k id mismatch: ${got_64k}"

got_4k="$(call_reader "6.1.87-ubuntu-4k+" "${grub_cfg}")"
[[ "${got_4k}" == "gnulinux-6.1.87-ubuntu-4k+-advanced-uuid" ]] || fail "4k id mismatch: ${got_4k}"

missing="$(call_reader "9.9.9-missing" "${grub_cfg}" || true)"
[[ -z "${missing}" ]] || fail "Expected empty result for missing kernel, got '${missing}'"

echo "All GRUB menu entry tests passed."
