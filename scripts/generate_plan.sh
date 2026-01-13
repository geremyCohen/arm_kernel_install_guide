#!/usr/bin/env bash
set -euo pipefail

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Required command '$1' not found in PATH." >&2
    exit 1
  }
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TEMPLATE_PATH="${REPO_ROOT}/plans/speedometer.yaml"
OUTPUT_DIR="${REPO_ROOT}/plans"
KERNEL_BASE="${HOME}/kernels"

sanitize_profile_name() {
  local raw="$1"
  local stripped
  stripped="$(printf '%s' "${raw}" | tr -cd 'A-Za-z0-9_.-')"
  if [[ -z "${stripped}" ]]; then
    echo "fp_profile"
  else
    echo "fp_${stripped}"
  fi
}

require_cmd yq

if [[ ! -f "${TEMPLATE_PATH}" ]]; then
  echo "Template ${TEMPLATE_PATH} was not found." >&2
  exit 1
fi
if [[ ! -d "${KERNEL_BASE}" ]]; then
  echo "Kernel directory ${KERNEL_BASE} does not exist." >&2
  exit 1
fi

read -rp "Enter SUT private IP: " SUT_IP
if [[ -z "${SUT_IP}" ]]; then
  echo "SUT private IP cannot be empty." >&2
  exit 1
fi

PLAN_SUFFIX="$(date +%m%d%y-%H%M)"
SUT_NAME="fastpath_test_${PLAN_SUFFIX}"
mkdir -p "${OUTPUT_DIR}"
OUTPUT_PATH="${OUTPUT_DIR}/${SUT_NAME}.yaml"

mapfile -t sorted_entries < <(LC_ALL=C ls -1t "${KERNEL_BASE}" 2>/dev/null || true)
selected_dirs=()
for entry in "${sorted_entries[@]}"; do
  [[ -n "${entry}" ]] || continue
  path="${KERNEL_BASE}/${entry}"
  [[ -d "${path}" ]] || continue
  [[ -f "${path}/Image.gz" && -f "${path}/modules.tar.xz" ]] || continue
  selected_dirs+=("${path}")
  (( ${#selected_dirs[@]} == 2 )) && break
done

if (( ${#selected_dirs[@]} < 2 )); then
  echo "Unable to find two kernel artifact directories under ${KERNEL_BASE}." >&2
  exit 1
fi

PROFILE0_RAW="$(basename "${selected_dirs[0]}")"
PROFILE0_NAME="$(sanitize_profile_name "${PROFILE0_RAW}")"
PROFILE0_KERNEL="${selected_dirs[0]}/Image.gz"
PROFILE0_MODULES="${selected_dirs[0]}/modules.tar.xz"
PROFILE1_RAW="$(basename "${selected_dirs[1]}")"
PROFILE1_NAME="$(sanitize_profile_name "${PROFILE1_RAW}")"
PROFILE1_KERNEL="${selected_dirs[1]}/Image.gz"
PROFILE1_MODULES="${selected_dirs[1]}/modules.tar.xz"

export PLAN_SUT_NAME="${SUT_NAME}"
export PLAN_SUT_IP="${SUT_IP}"
export PLAN_PROFILE0_NAME="${PROFILE0_NAME}"
export PLAN_PROFILE0_KERNEL="${PROFILE0_KERNEL}"
export PLAN_PROFILE0_MODULES="${PROFILE0_MODULES}"
export PLAN_PROFILE1_NAME="${PROFILE1_NAME}"
export PLAN_PROFILE1_KERNEL="${PROFILE1_KERNEL}"
export PLAN_PROFILE1_MODULES="${PROFILE1_MODULES}"

FILTER='.sut.name = env.PLAN_SUT_NAME | .sut.connection.params.host = env.PLAN_SUT_IP | .swprofiles = [{name: env.PLAN_PROFILE0_NAME, kernel: env.PLAN_PROFILE0_KERNEL, modules: env.PLAN_PROFILE0_MODULES}, {name: env.PLAN_PROFILE1_NAME, kernel: env.PLAN_PROFILE1_KERNEL, modules: env.PLAN_PROFILE1_MODULES}]'
yq -y "${FILTER}" "${TEMPLATE_PATH}" > "${OUTPUT_PATH}"

INFO_COLOR='\033[1;36m'
RESET_COLOR='\033[0m'
heading() { printf '%b%s%b\n' "${INFO_COLOR}" "$1" "${RESET_COLOR}"; }

heading "Plan name:"
echo "  ${SUT_NAME}"
echo
heading "Plan written to:"
echo "  ${OUTPUT_PATH}"
echo
heading "Run Fastpath with:"
echo "  ~/fastpath/fastpath/fastpath plan exec --output results/ ${OUTPUT_PATH}"
echo
heading "After Fastpath run completes, gather results with:"
echo "  ~/fastpath/fastpath/fastpath result list results/ --object swprofile"
echo
heading "Relative results per kernel:"
echo "  ~/fastpath/fastpath/fastpath result show results/ --swprofile ${PROFILE0_NAME} --relative"
echo "  ~/fastpath/fastpath/fastpath result show results/ --swprofile ${PROFILE1_NAME} --relative"
echo
heading "Comparison between kernels:"
echo "  ~/fastpath/fastpath/fastpath result show results/ --swprofile ${PROFILE0_NAME} --swprofile ${PROFILE1_NAME} --relative"
