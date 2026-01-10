## Kernel Test Suite Execution Prompt

Use this prompt whenever you need to rebuild context for the end-to-end test sweep defined in `.codex/test_kernel_build.md`.

1. **Goal**  
   - Run *every* command in `.codex/test_kernel_build.md` while minimizing redundant compiles.  
   - Batch all build-heavy tests first, archive their outputs, then reuse those artifacts for install-only scenarios.  
   - Capture logs, track pass/fail, and only start fixing bugs after one full sweep is recorded.

2. **Two-phase execution model**  
   - **Phase A – Build batch**:  
     - Prioritize every test that produces new artifacts (flat, dpkg, 64K, fastpath, etc.).  
     - Use a c8g.24xlarge host for each build test. While a build is running, any additional 24xl hosts should be *stopped* (not terminated) to avoid idle charges; terminate once the queued builds finish and artifacts are copied off.  
     - After each build, tar the generated kernel folder(s) plus `.deb` files (if any) into `~/artifacts/<test-id>/<tag>-flat.tgz` or `...-deb.tgz`. Copy these back to the local repo under `test-artifacts/<test-id>/`.  
     - Document the mapping of “Test → artifact bundle” in a manifest table (see Tracking).  
   - **Phase B – Install/validation batch**:  
     - For tests that only consume previously-built artifacts (`--install-from`, mixed-tag installs, etc.), start fresh c8g.8xlarge hosts.  
     - Before provisioning, check `test-artifacts/` for the required bundle; if missing, rebuild that kernel in Phase A first.  
     - Copy the needed archive to the host, extract into `~/kernels`, and run the install command.  
     - For multi-tag installs, stage all required bundles before invoking the script.

3. **Environment setup per host**  
   - `export AWS_DEFAULT_PROFILE=arm` and region `us-east-1`.  
   - Launch a new instance with the standard `aws ec2 run-instances … --tag Name=gcohen-qa1229-<test>` command (same block-device/security config we’ve been using).  
   - Poll `aws ec2 describe-instances` for the public IP; `ssh -A` in with host-key acceptance.  
   - `sudo apt-get update && sudo apt-get install -y git`, then `git clone https://github.com/geremyCohen/arm_kernel_install_guide.git`, `cd` into it, and `git checkout qa_1229`.  
   - Create `~/kernels` and `~/logs`.

4. **Per-test execution**  
   - Before running a test, `rm -rf ~/kernels && mkdir ~/kernels`.  
   - Execute the exact command from `.codex/test_kernel_build.md` with `set -o pipefail` and pipe output to `~/logs/testXX.log`.  
   - Record verification steps noted in the test (`uname -r`, `getconf PAGE_SIZE`, `fastpath --help`, etc.).  
   - During Phase A, archive outputs immediately after the build completes and before terminating/stopping the 24xl host.  
   - During Phase B, pull the necessary archive from `test-artifacts/`, extract, and proceed with the install-only command. Note in the log which artifact bundle was used.

5. **Host lifecycle rules**  
   - Build hosts (24xl) may be *stopped* while idle between sequential build tests to save cost, but should be terminated once their queued builds are complete and artifacts uploaded.  
   - Install-only hosts (8xl) should be terminated immediately after their test finishes.  
   - Never reuse a host for two distinct tests within the same boot session; always start from a clean state (either by launching a new host or by stop/start with `~/kernels` wiped before resuming).  
   - Track instance IDs and ensure none remain running when not executing a test.

6. **Tracking & manifests**  
   - Maintain a table with columns: Test #, Command, Host/IP, Instance ID, Host Type (24xl/8xl), Status, Log Path, Artifact bundle (if produced/consumed).  
   - For each artifact, note: source test, kernel tags, page-size mode, format (flat/deb), storage path under `test-artifacts/`.  
   - For failing tests, capture the relevant log excerpt and system state but continue executing the remaining tests on fresh hosts. No code changes until all tests have results.

7. **After full sweep**  
   - Summarize pass/fail, list bugs, then plan fixes.  
   - Apply fixes on a new branch, rerun the *entire* suite using the same phased process.  
   - When everything passes, confirm all EC2 instances are terminated or stopped (build hosts) and `aws ec2 describe-instances` shows no unintended running machines.

Keep this workflow consistent so we can resume seamlessly if context is lost.
