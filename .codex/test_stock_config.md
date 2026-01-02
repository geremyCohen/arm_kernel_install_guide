## Stock Config Preservation & Pull Test

1. On the build SUT (e.g., 13.218.155.222), clone the `preserve-stock-config` branch and run `./scripts/kernel_build_and_install.sh --tag v6.18` (use `v6.18` since there is no `v6.18.0` tag). Confirm `~/kernels/6.18.0` contains `config.stock` alongside the usual artifacts and that `~/kernels/stock-configs/config-<running-kernel>` was created.
2. From the Fastpath host (e.g., 54.172.102.176), run `./scripts/pull_kernel_artifacts.sh --host 13.218.155.222 --assume-yes` and verify `~/kernels/6.18.0/config.stock` exists locally.
3. Determine the two most recent stable tags via `git ls-remote` (currently `v6.18.2` and `v6.18.1`).
4. On the SUT, run `./scripts/kernel_build_and_install.sh --tags v6.18.2,v6.18.1` to trigger parallel builds.
5. Verify `~/kernels/6.18.1/config.stock` and `~/kernels/6.18.2/config.stock` exist along with the other artifacts.
6. On the Fastpath host, rerun the pull script (`./scripts/pull_kernel_artifacts.sh --host 13.218.155.222 --assume-yes`).
7. Confirm `~/kernels/6.18.1` and `~/kernels/6.18.2` on the Fastpath host each contain `Image.gz`, `modules.tar.xz`, and `config.stock`.
