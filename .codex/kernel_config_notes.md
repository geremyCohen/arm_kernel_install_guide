# Kernel Config Preservation Notes

- `kernel_build_and_install.sh` now captures the source config (defaults to `/boot/config-$(uname -r)` unless `--config-file` overrides it) once per build run, copies it into every output directory as `config.stock`, and archives a copy under `~/kernels/stock-configs/config-<running-kernel>`. This preserves the "stock" vendor config even after Fastpath installs a different kernel.
- `pull_kernel_artifacts.sh` pulls `config.stock` in addition to `Image.gz` and `modules.tar.xz`, so each Fastpath host mirrors the SUT’s stock config for every kernel version it grabs.
- When we introduce the Fastpath wrapper script, we’ll extend this behavior so the wrapper automatically restores the stock config after Fastpath completes its tests.
