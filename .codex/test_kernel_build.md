## Kernel Build Test Matrix

Use the multi-kernel build script to validate concurrent and single builds on a clean SUT.

Before each run, delete ~/kernels on the SUT. Verify tuxmake reports PASS for every requested target and that artifacts land under ~/kernels/<kernel_version>.

On systems that don't require building, use a c8g.8xl.  For systems that do require building, use a c8g.24xl.


./scripts/kernel_build_and_install.sh --demo-default-build # verify single-tag (v6.18.1) build without fastpath and ensure docker is NOT installed.

./scripts/kernel_build_and_install.sh --demo-fastpath-build # verify two-tag build with fastpath configs and confirm docker IS installed.

./scripts/kernel_build_and_install.sh --tags v6.19-rc1 # Build a single RC tag; confirm artifacts land under ~/kernels/<rc_version> and docker.io remains uninstalled.

./scripts/kernel_build_and_install.sh --tags v6.18.1,v6.19-rc1 --include-bindeb-pkg # Verify DEB packages are created.

./scripts/kernel_build_and_install.sh --tags v6.14,v6.18.1

./scripts/kernel_build_and_install.sh --tags v6.18.1,v6.19-rc1

./scripts/kernel_build_and_install.sh --tags v6.18.1 # Baseline compile; confirm docker.io is NOT installed (e.g. `dpkg -l docker.io` has no rows) since no fastpath options were used.

./scripts/kernel_build_and_install.sh --tags v6.18.1 --include-bindeb-pkg # Verify DEB packages are created.

./scripts/kernel_build_and_install.sh --tags v6.18.1 --kernel-install true # System should reboot automatically. Wait 1m to relogin, and verify that new kernel is installed and running.

./scripts/kernel_build_and_install.sh --tag-latest # Build the latest stable kernel and verify artifacts appear under ~/kernels/<latest>.

./scripts/kernel_build_and_install.sh --tags v6.18.1 --change-to-64k true --kernel-install true # After the automatic reboot, verify uname -r matches the build and `getconf PAGE_SIZE` returns 65536.

./scripts/kernel_build_and_install.sh --tags v6.18.1 --config-file ~/kernels/stock-configs/config-6.14.0-1015-aws # Build using a preserved stock config.

./scripts/kernel_build_and_install.sh --tags v6.18.1 --change-to-64k true --include-bindeb-pkg --kernel-install true # Confirm .deb artifacts exist, wait for the automatic reboot, then verify uname -r and `getconf PAGE_SIZE` show the installed 64K kernel.

./scripts/kernel_build_and_install.sh --tags v6.18.1,v6.19-rc1 --kernel-install v6.18.1 # Multi-tag build: install only the specified tag, allow the automatic reboot, and verify uname -r matches v6.18.1 while both tag outputs exist under ~/kernels.

./scripts/kernel_build_and_install.sh --tags v6.18.1,v6.19-rc1 --kernel-install # Expect immediate failure: when more than one tag is requested, the install flag must name the tag to install.

./scripts/kernel_build_and_install.sh --tags v6.18.1,v6.19-rc1 --kernel-install v6.20.0 # Expect immediate failure: requested install tag must match one of the tags passed to --tag/--tags.

./scripts/kernel_build_and_install.sh --install-from ~/kernels/6.18.1 --install-format flat # After building but skipping install, reuse the saved flat artifacts; the script reboots automatically and uname -r should match the installed kernel.

./scripts/kernel_build_and_install.sh --install-from ~/kernels/6.18.1 --install-format deb # After building with --include-bindeb-pkg, install from the generated .deb files, wait for the automatic reboot, and confirm uname -r plus dpkg -l show the new kernel packages.

./scripts/kernel_build_and_install.sh --install-from ~/kernels/6.18.1 # Auto-detect install format; ensure the directory already contains either flat artifacts or .deb packages, then let the automatic reboot occur and verify uname -r matches the installed kernel.

./scripts/kernel_build_and_install.sh --tags v6.18.1,v6.19-rc1 --fastpath true # Explicit Fastpath build; confirm docker.io is installed and both tag directories contain Fastpath configs. Fastpath runs are build-only—never combine --fastpath with install flags.
