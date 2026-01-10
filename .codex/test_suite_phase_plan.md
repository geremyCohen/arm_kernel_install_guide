## qa_1229 Phase Plan (test-suite-optimization branch)

### Preflight (no build, c8g.8xl)
1. Test 2 – `--help` (doc parity)
2. Test 4 – `--dry-run` (verifies plan script)
3. Failure validations (Tests 17 & 18) – ensure argument validation trips before build.

### Phase A – Build producers (c8g.24xl)
1. Test 1 – `--demo-default-build` → artifacts: `6.18.1-ubuntu` flat only.
2. Test 3 – `--demo-fastpath-build` → artifacts: `6.18.1-ubuntu+` & `6.19.0-rc1-ubuntu+` (fastpath configs).
3. Test 5 – `--tags v6.19-rc1`
4. Test 6 – `--tags v6.18.1,v6.19-rc1 --include-bindeb-pkg` → produces flat + deb for both tags.
5. Test 7 – `--tags v6.14,v6.18.1`
6. Test 8 – `--tags v6.18.1,v6.19-rc1`
7. Test 9 – `--tags v6.18.1` (baseline flat)
8. Test 10 – `--tags v6.18.1 --include-bindeb-pkg`
9. Test 11 – `--tags v6.18.1 --kernel-install true` (capture flat artifacts post-build before reboot)
10. Test 12 – `--tag-latest`
11. Test 13 – `--tags v6.18.1 --change-to-64k true --kernel-install true --append-to-kernel-version "-64k"` (flat 64K)
12. Test 14 – `--tags v6.18.1 --config-file ~/kernels/stock-configs/config-6.14.0-1015-aws`
13. Test 15 – `--tags v6.18.1 --change-to-64k true --include-bindeb-pkg --kernel-install true --append-to-kernel-version "-64k"` (64K flat+deb)
14. Test 16 – `--tags v6.18.1,v6.19-rc1 --kernel-install v6.18.1`
24xl hosts: stop between builds when idle; terminate once artifacts copied back.

### Phase B – Install/consumers (c8g.8xl)
1. Test 19 – install-from flat (6.18.1)
2. Test 20 – install-from deb (6.18.1)
3. Test 21 – install-from flat 64K
4. Test 22 – install-from deb 64K
5. Test 23 – auto-detect install format
6. Test 24 – fastpath build-only validation (already produced in Phase A but needs rerun to observe docker state)

### Artifact handling
- Store archives under `test-artifacts/testXX/<tag>-<format>.tgz` with README noting source test/output options.
- Manifest CSV columns: `test_id, command, artifact_path, kernel_tags, format, notes`.

### Logging & shutdown
- Logs on host: `~/logs/testXX.log`. Copy to `test-artifacts/testXX/`. 
- Terminate 8xl immediately. For 24xl, stop when pausing, terminate when finished with queued builds.
