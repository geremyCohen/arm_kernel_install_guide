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

PROFILE0_NAME="$(basename "${selected_dirs[0]}")"
PROFILE0_KERNEL="${selected_dirs[0]}/Image.gz"
PROFILE0_MODULES="${selected_dirs[0]}/modules.tar.xz"
PROFILE1_NAME="$(basename "${selected_dirs[1]}")"
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

FILTER='.sut.name = env(PLAN_SUT_NAME) | .sut.connection.params.host = env(PLAN_SUT_IP) | .swprofiles = [{name: env(PLAN_PROFILE0_NAME), kernel: env(PLAN_PROFILE0_KERNEL), modules: env(PLAN_PROFILE0_MODULES)}, {name: env(PLAN_PROFILE1_NAME), kernel: env(PLAN_PROFILE1_KERNEL), modules: env(PLAN_PROFILE1_MODULES)}]'
if yq --version 2>&1 | grep -qi 'https://github.com/mikefarah/yq'; then
  yq eval "${FILTER}" "${TEMPLATE_PATH}" > "${OUTPUT_PATH}"
else
  python3 - "${TEMPLATE_PATH}" "${OUTPUT_PATH}" <<'PY'
import json, os, sys, yaml
filter_kwargs = {
    "sut_name": os.environ["PLAN_SUT_NAME"],
    "sut_ip": os.environ["PLAN_SUT_IP"],
    "profile0_name": os.environ["PLAN_PROFILE0_NAME"],
    "profile0_kernel": os.environ["PLAN_PROFILE0_KERNEL"],
    "profile0_modules": os.environ["PLAN_PROFILE0_MODULES"],
    "profile1_name": os.environ["PLAN_PROFILE1_NAME"],
    "profile1_kernel": os.environ["PLAN_PROFILE1_KERNEL"],
    "profile1_modules": os.environ["PLAN_PROFILE1_MODULES"],
}
template, target = sys.argv[1], sys.argv[2]
with open(template, "r", encoding="utf-8") as fh:
    data = yaml.safe_load(fh)
data.setdefault("sut", {})
data["sut"]["name"] = filter_kwargs["sut_name"]
data["sut"].setdefault("connection", {}).setdefault("params", {})["host"] = filter_kwargs["sut_ip"]
data["swprofiles"] = [
    {
        "name": filter_kwargs["profile0_name"],
        "kernel": filter_kwargs["profile0_kernel"],
        "modules": filter_kwargs["profile0_modules"],
    },
    {
        "name": filter_kwargs["profile1_name"],
        "kernel": filter_kwargs["profile1_kernel"],
        "modules": filter_kwargs["profile1_modules"],
    },
]
with open(target, "w", encoding="utf-8") as fh:
    yaml.safe_dump(data, fh, sort_keys=False)
PY
fi

echo "Plan written to ${OUTPUT_PATH}"
echo "Generated plan name: ${SUT_NAME}"
echo
echo "Run Fastpath with:"
echo "  fastpath plan exec --output results/ ${OUTPUT_PATH}"
echo
echo "After Fastpath run completes, gather results with:"
echo "  fastpath result list results/ --object swprofile"
echo
echo "Relative results per kernel:"
echo "  fastpath result show results/ --swprofile ${PROFILE0_NAME} --relative"
echo "  fastpath result show results/ --swprofile ${PROFILE1_NAME} --relative"
echo
echo "Comparison between kernels:"
echo "  fastpath result show results/ --swprofile ${PROFILE0_NAME} --swprofile ${PROFILE1_NAME} --relative"
