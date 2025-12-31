## Stock Config Preservation Refresher

Use this prompt when you need to recall how the repo preserves kernel configs or when you’re ready to build the Fastpath wrapper that restores them automatically.

1. **What the build script does now**
   - `kernel_build_and_install.sh` resolves the “source” config once (defaults to `/boot/config-$(uname -r)` unless `--config-file` overrides it).  
   - `preserve_source_config()` copies that file into every build output as `config.stock` **and** into `~/kernels/stock-configs/config-<running-kernel>` before any Fastpath or tuxmake changes occur.
   - Result: even if Fastpath later replaces `/boot/config-*`, the original vendor config is still available both inside each kernel artifact bundle and under `~/kernels/stock-configs/`.

2. **What the pull script does**
   - `pull_kernel_artifacts.sh` copies `config.stock` alongside `Image.gz` and `modules.tar.xz` whenever it pulls a kernel version to the Fastpath host.  
   - The Fastpath host therefore mirrors each preserved config, keeping flat artifacts + `config.stock` together.

3. **Why preservation was needed**
   - After Fastpath (or any install) reboots the SUT into a custom kernel, `/boot/config-$(uname -r)` reflects that new build, and the cloud-vendor baseline config is gone or stale.  
   - Without our preservation step, running the build script again would unknowingly inherit the Fastpath-tuned config instead of the original AWS stock config.

4. **Outstanding wrapper work**
   - We still need a Fastpath wrapper that, after Fastpath testing completes, copies the preserved stock config back into place (or feeds it to future builds automatically).  
   - The wrapper should: (a) reference `~/kernels/stock-configs/config-<stock-kernel>` to know which baseline to restore, (b) copy or symlink that file back to `/boot/config-<stock>` (or a designated location) once Fastpath is done, and (c) optionally hand that path to `kernel_build_and_install.sh --config-file` on subsequent builds.

5. **Related docs/tests**
   - `.codex/kernel_config_notes.md` summarizes this behavior.
   - `.codex/test_stock_config.md` walks through the validation steps (single build, dual build, pull) to confirm `config.stock` exists on both SUT and Fastpath hosts.

Keep this summary handy when context is lost or when it’s time to implement the Fastpath wrapper logic.
