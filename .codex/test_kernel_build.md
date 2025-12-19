## Kernel Build Test Matrix

Use the multi-kernel build script to validate concurrent and single builds on a clean SUT.

0.   ./scripts/kernel_build_and_install.sh --tags v6.18.1,v6.19-rc1 --assume-yes --include-bindeb-pkg # Verify DEB packages are created.

1. ./scripts/kernel_build_and_install.sh --tags v6.14,v6.18.1 --assume-yes

2./scripts/kernel_build_and_install.sh --tags v6.18.1,v6.19-rc1 --assume-yes
3. ./scripts/kernel_build_and_install.sh --tags v6.18.1 --assume-yes

4. ./scripts/kernel_build_and_install.sh --tags v6.18.1 --assume-yes --include-bindeb-pkg # Verify DEB packages are created.

5. ./scripts/kernel_build_and_install.sh --tags v6.18.1 --assume-yes --kernel-install true # System should reboot.  Wait 1m to relogin, and verify that new kernel is installed and running 

Before each run, delete ~/kernels on the SUT. Verify tuxmake reports PASS for every requested target and that artifacts land under ~/kernels/<kernel_version>.

Shortcut: `./scripts/kernel_build_and_install.sh --demo-fastpath-builds` runs step 2 with `--assume-yes` automatically.
