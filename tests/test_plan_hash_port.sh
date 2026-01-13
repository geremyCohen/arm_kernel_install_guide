#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_PATH="${REPO_ROOT}/scripts/kernel_build_and_install.sh"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

expected_hash() {
  python3 - "$@" <<'PY'
import hashlib, sys
args = sys.argv[1:]
if not args:
    data = b'defaults'
else:
    data = ('\n'.join(args) + '\n').encode()
print(hashlib.sha256(data).hexdigest()[:10])
PY
}

extract_hash_from_plan() {
  local plan_path="$1"
  local base hash
  base="$(basename "${plan_path}")"
  hash="${base%.sh}"
  hash="${hash##*_}"
  printf '%s\n' "${hash}"
}

run_case() {
  local name="$1"
  shift
  local -a args=("$@")
  echo "Running ${name}..."
  local plan_path
  if (( ${#args[@]} == 0 )); then
    plan_path="$("${SCRIPT_PATH}" --dry-run)"
  else
    plan_path="$("${SCRIPT_PATH}" --dry-run "${args[@]}")"
  fi
  [[ -n "${plan_path}" && -f "${plan_path}" ]] || fail "Plan not created for ${name}"
  local expected actual
  if (( ${#args[@]} == 0 )); then
    expected="$(expected_hash)"
  else
    expected="$(expected_hash "${args[@]}")"
  fi
  actual="$(extract_hash_from_plan "${plan_path}")"
  rm -f "${plan_path}"
  if [[ "${expected}" != "${actual}" ]]; then
    fail "${name}: expected hash ${expected}, got ${actual}"
  fi
}

run_case "defaults (no args)" 
run_case "tags + append" --tags v6.18.1,v6.19-rc1 --append-to-kernel-version "-lab"
run_case "kernel cmdline with spaces" --tags v6.18.1 --kernel-command-line "root=/dev/vda1 console=ttyS0"

echo "All plan hash tests passed."
