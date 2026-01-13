#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_PATH="${REPO_ROOT}/scripts/kernel_build_and_install.sh"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

call_reader() {
  local dir="$1"
  local fallback="$2"
  bash -c "source '${SCRIPT_PATH}'; detect_artifact_kernel_release '${dir}' '${fallback}'"
}

make_tarball() {
  local dir="$1"
  local version="$2"
  local tmp="$dir/tmp"
  mkdir -p "${tmp}/lib/modules/${version}"
  touch "${tmp}/lib/modules/${version}/placeholder"
  (cd "${tmp}" && tar -cJf "${dir}/modules.tar.xz" lib)
  rm -rf "${tmp}"
}

run_case() {
  local name="$1"
  local setup_fun="$2"
  local expect="$3"
  local tmp
  tmp="$(mktemp -d)"
  trap "rm -rf '${tmp}'" RETURN
  ${setup_fun} "${tmp}"
  local got
  got="$(call_reader "${tmp}" "fallback")"
  if [[ "${got}" != "${expect}" ]]; then
    fail "${name}: expected '${expect}', got '${got}'"
  fi
  trap - RETURN
  rm -rf "${tmp}"
  echo "Passed: ${name}"
}

setup_metadata_only() {
  local dir="$1"
  cat >"${dir}/metadata.json" <<'EOF'
{"source":{"kernelrelease":"6.18.1-custom"}}
EOF
}

setup_metadata_empty() {
  local dir="$1"
  cat >"${dir}/metadata.json" <<'EOF'
{"source":{}}
EOF
}

setup_tar_only() {
  local dir="$1"
  make_tarball "${dir}" "6.19.0-rc1-test"
}

setup_both_metadata_wins() {
  local dir="$1"
  setup_metadata_only "${dir}"
  make_tarball "${dir}" "tar-version"
}

setup_tar_no_match() {
  local dir="$1"
  local empty
  empty="$(mktemp -d)"
  tar -cJf "${dir}/modules.tar.xz" -C "${empty}" .
  rm -rf "${empty}"
}

run_case "metadata present" setup_metadata_only "6.18.1-custom"
run_case "metadata empty uses fallback" setup_metadata_empty "fallback"
run_case "metadata missing uses fallback" setup_tar_no_match "fallback"
run_case "tarball fallback" setup_tar_only "6.19.0-rc1-test"
run_case "metadata wins over tar" setup_both_metadata_wins "6.18.1-custom"

echo "All metadata reader tests passed."
