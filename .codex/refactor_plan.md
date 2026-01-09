## Refactor & Cleanup Plan

1. **Remove unused kernel source overrides**
   - Drop `--repo` / `--branch` options plus their plumbing from `scripts/kernel_build_and_install.sh`.
   - Update help text and docs once the CLI surface shrinks.

2. **Simplify Fastpath host setup CLI**
   - Remove `--ssh-user` flag/support from `scripts/configure_fastpath_host.sh` (always use default ubuntu).
   - Update Fastpath LP/docs to match the reduced interface.

3. **Simplify SUT configuration script**
   - Drop `--ssh-user` and `--fp-user` options from `scripts/configure_fastpath_sut.sh`, baking in the documented defaults.
   - Reflect the streamlined usage anywhere it’s referenced (learning path, tests).

4. **Trim pull_kernel_artifacts.sh surface**
   - Remove override flags (`--ssh-user`, `--remote-dir`, `--local-dir`, `--version`) so the script strictly follows the documented workflow.
   - Update Fastpath LP snippets to match the simplified usage if needed.
