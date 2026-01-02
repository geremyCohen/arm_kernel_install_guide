#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TEMPLATE_PATH="${REPO_ROOT}/plans/speedometer.yaml"
OUTPUT_PATH="${REPO_ROOT}/plan.yaml"

if [[ ! -f "${TEMPLATE_PATH}" ]]; then
  echo "Template ${TEMPLATE_PATH} was not found." >&2
  exit 1
fi

read -rp "Enter SUT private IP: " SUT_IP
if [[ -z "${SUT_IP}" ]]; then
  echo "SUT private IP cannot be empty." >&2
  exit 1
fi

PLAN_SUFFIX="$(date +%m%d%y-%H%M)"
SUT_NAME="fastpath_test_${PLAN_SUFFIX}"

python3 - "${TEMPLATE_PATH}" "${OUTPUT_PATH}" "${SUT_IP}" "${SUT_NAME}" <<'PY'
import sys
import pathlib

try:
    import yaml
except ImportError:
    sys.stderr.write(
        "PyYAML is required for generate_plan.sh. Install it with "
        "'python3 -m pip install pyyaml'.\n"
    )
    sys.exit(1)

template_path, output_path, sut_ip, sut_name = sys.argv[1:5]

with open(template_path, "r", encoding="utf-8") as fh:
    data = yaml.safe_load(fh)

base_dir = pathlib.Path.home() / "kernels"
candidates = []
if base_dir.exists():
    for child in base_dir.iterdir():
        if not child.is_dir():
            continue
        if (child / "Image.gz").is_file() and (child / "modules.tar.xz").is_file():
            candidates.append((child.stat().st_mtime, child))

if len(candidates) < 2:
    sys.stderr.write(
        f"Need at least two kernel artifact directories under {base_dir}, "
        f"but found {len(candidates)}.\n"
    )
    sys.exit(1)

candidates.sort(key=lambda item: item[0], reverse=True)
selected = [path for _, path in candidates[:2]]

existing_cmdlines = []
for profile in (data.get("swprofiles") or []):
    existing_cmdlines.append(profile.get("cmdline"))

profiles = []
for idx, path in enumerate(selected):
    entry = {
        "name": path.name,
        "kernel": str(path / "Image.gz"),
        "modules": str(path / "modules.tar.xz"),
    }
    if idx < len(existing_cmdlines) and existing_cmdlines[idx]:
        entry["cmdline"] = existing_cmdlines[idx]
    profiles.append(entry)

data.setdefault("sut", {})
data["sut"]["name"] = sut_name
conn = data["sut"].setdefault("connection", {})
params = conn.setdefault("params", {})
params["host"] = sut_ip
data["swprofiles"] = profiles

with open(output_path, "w", encoding="utf-8") as fh:
    yaml.safe_dump(data, fh, sort_keys=False)
PY

echo "Plan written to ${OUTPUT_PATH}"
echo "Generated plan name: ${SUT_NAME}"
