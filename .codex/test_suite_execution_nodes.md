## Kernel Test Suite Execution Prompt

Use this prompt whenever you need to rebuild context for the `qa_1229` end-to-end test sweep defined in `.codex/test_kernel_build.md`.

1. **Goal**: Run *every* command in `.codex/test_kernel_build.md` on clean c8g.24xlarge Ubuntu-arm hosts, capture logs, archive required artifacts, record pass/fail, and only after the full sweep address bugs/fixes.
2. **Environment setup per host**  
   - `export AWS_DEFAULT_PROFILE=arm` and region `us-east-1`.  
   - Launch a new instance with the standard `aws ec2 run-instances … --tag Name=qa1229-<test>` command (same block-device/security config we’ve been using).  
   - Poll `aws ec2 describe-instances` for the public IP; `ssh -A` in with host-key acceptance.  
   - `sudo apt-get update && sudo apt-get install -y git`, then `git clone https://github.com/geremyCohen/arm_kernel_install_guide.git`, `cd` into it, and `git checkout qa_1229`.  
   - Create `~/kernels` and `~/logs`.
3. **Per-test execution**  
   - Before running a test, `rm -rf ~/kernels && mkdir ~/kernels`.  
   - Execute the exact command from `.codex/test_kernel_build.md` with `set -o pipefail` and pipe output to `~/logs/testXX.log`.  
   - Record verification steps noted in the test (e.g., `dpkg -l docker.io`, `uname -r`, `getconf PAGE_SIZE`, checking `.deb` output, etc.).  
   - For install-only scenarios (`--install-from …`), check the local `test-artifacts/` directory *before* provisioning the host so you know whether the required tarball/`deb` bundle already exists. If the artifact is missing or outdated, rebuild it first by rerunning the corresponding build test, archive the result under `test-artifacts/`, and then proceed with the install-only step by copying that archive to the host.
   - If artifacts are needed later (install-from tests), tar the specific `~/kernels/<tag>` directory (or `.deb` files) into `~/artifacts/<descriptive>.tgz`, then `scp -A` them back to `test-artifacts/` locally.
4. **Host lifecycle**  
   - After each test (pass or fail), copy any required artifacts/logs off the host.  
   - Immediately terminate that instance with `aws ec2 terminate-instances --instance-ids <id>` to avoid idle machines.  
   - Never reuse a host for a second test; always provision fresh.
5. **Tracking**  
   - Maintain a table (locally) with columns: Test #, Command, Host/IP, Instance ID, Status, Log Path, Artifacts.  
   - For failing tests, capture the relevant log excerpt and system state but still continue executing the remaining tests on fresh hosts. No code changes until all tests have results.
6. **After full sweep**  
   - Summarize pass/fail, list bugs, then plan fixes.  
   - After applying fixes, repeat the *entire* suite with the same process.  
   - When everything passes, confirm all EC2 instances are terminated (`aws ec2 describe-instances` shows `terminated`).

Keep this workflow consistent so we can resume seamlessly if context is lost.
