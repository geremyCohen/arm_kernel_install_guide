## Kernel Build Test Matrix

Use the multi-kernel build script to validate concurrent and single builds on a clean SUT.

1. ./scripts/kernel_build_and_install.sh --tags v6.14,v6.18.1 --assume-yes
2. ./scripts/kernel_build_and_install.sh --tags v6.18.1,v6.19-rc1 --assume-yes
3. ./scripts/kernel_build_and_install.sh --tags v6.18.1 --assume-yes

Before each run, delete ~/kernels on the SUT. Verify tuxmake reports PASS for every requested target and that artifacts land under ~/kernels/<kernel_version>.
