## Kernel Artifact Pull Test

1. Ensure the kernel build host has at least one completed build under `~/kernels/<tag>/` containing `Image.gz`, `modules.tar.xz`, and `config.stock` (e.g., run the multi-kernel build tests first).
2. From the Fastpath host, fetch the script if needed (`scp scripts/pull_kernel_artifacts.sh ubuntu@<FASTPATH_HOST>:~/`).
3. SSH to the Fastpath host (`ssh ubuntu@<FASTPATH_HOST>`) and run:
   `bash ~/pull_kernel_artifacts.sh --host <KERNEL_HOST> --assume-yes`
4. Confirm it logs the detected versions, copies only missing artifacts, and places them under `~/kernels/<tag>/` locally.
5. Re-run the command; expect "All artifacts already present" messages with no additional transfers.
6. Spot check `ls ~/kernels/<tag>` to verify `Image.gz`, `modules.tar.xz`, and `config.stock` are present locally.

Substitute `<FASTPATH_HOST>` (e.g., 54.172.102.176) and `<KERNEL_HOST>` (e.g., 50.17.32.197) as appropriate.
