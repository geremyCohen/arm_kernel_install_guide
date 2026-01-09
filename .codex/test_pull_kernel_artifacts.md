## Kernel Artifact Pull Test

1. Ensure the kernel build host has at least one completed build under `~/work/kernel-builds/fastpath/<tag>/` with `Image.gz`, `modules.tar.xz`, and `config.stock` (run any of the kernel_build tests first if needed).
2. On the Fastpath host, clone/update this repo and `cd ~/arm_kernel_install_guide`.
3. Run `./scripts/pull_kernel_artifacts.sh --host <KERNEL_HOST>` with no additional flags (the script always connects as ubuntu, copies from `~/work/kernel-builds/fastpath`, and stores results under `~/kernels`).
4. Confirm the output lists the detected versions, copies only missing artifacts, and places them under `~/kernels/<tag>/` locally.
5. Re-run the command; expect "All artifacts already present" messages with no additional transfers.
6. Spot check `ls ~/kernels/<tag>` to verify `Image.gz`, `modules.tar.xz`, and `config.stock` are present locally.

Substitute `<FASTPATH_HOST>` (e.g., 54.172.102.176) and `<KERNEL_HOST>` (e.g., 50.17.32.197) as appropriate.
