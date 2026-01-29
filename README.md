# Arm Linux Kernel Install Guide

This repository provides supporting material for building, installing, and deploying **custom Linux kernels on Arm cloud instances**.

It is designed to be used alongside the associated Arm Learning Path

**Build Linux kernels for Arm cloud instances**  available at:
https://learn.arm.com/learning-paths/servers-and-cloud-computing/kernel-build/

This repository contains the companion scripts referenced throughout the course. The Learning Path provides the full context, explanations, and step-by-step guidance for using these scripts effectively. 

> [!NOTE]
> Backup any important data, and always test kernels installs on 
> non-production systems first to avoid potential downtime or data loss.  

---

## Prerequisites

- An Arm‑based Linux cloud instance (Ubuntu 24 on AWS recommended)
- SSH access between systems

> [!NOTE]
> These scripts and associated learning path have been officially tested on Arm
> cloud instances running Ubuntu 24.04 LTS on AWS.  New users are encouraged to
> start with this configuration to mitigate unexpected issues.

---

## Repository Layout

The repository contains the following files:

```
.
├── kernel_build_and_install.sh
├── pull_kernel_artifacts.sh
├── configure_fastpath_host.sh
├── configure_fastpath_sut.sh
├── generate_plan.sh
├── plans/
    └── speedometer.yaml
```

More detailed info on each script is displayed below.  (This section is optional to read if you plan to follow the Learning Path directly.)

### `kernel_build_and_install.sh`

The main entry point for building and optionally installing Linux kernels.

This script:
- Clones the Linux kernel source from kernel.org
- Checks out a specified branch or tag
- Builds kernel images, modules, and optional Debian packages
- Optionally installs the kernel on the local system

#### Usage

```text
Usage: kernel_build_and_install.sh [options]

Options:
  --tag <tag>                     Kernel tag to build (default: latest on branch)
  --branch <branch>               Kernel branch to use
  --config <file>                 Kernel config file to apply
  --append-version <string>       Append string to kernel version
  --cmdline <string>              Kernel command line parameters
  --install                       Install the kernel after build
  --install-target <device>       Install target (e.g. root disk)
  --64k                           Build kernel with 64K page size
  --fastpath                      Enable Fastpath kernel build options
  --kernel-dir <path>             Kernel source directory
  --output-dir <path>             Output directory for build artifacts
  --include-bindeb                Build Debian kernel packages
  --demo-fastpath                 Build multiple Fastpath demo kernels
  --demo-default                  Build default demo kernel
  --requires-docker               Enable docker-based build
  --dry-run                       Print actions without executing
  -h, --help                      Show this help message
```

---

### `pull_kernel_artifacts.sh`

Pulls previously built kernel artifacts from a remote build host.

This script:
- Connects to a remote Arm instance over SSH
- Downloads, then stores kernel artifacts locally under `~/kernels`

Useful when kernel builds are performed on a dedicated build system and
installed or tested elsewhere.

#### Usage

```text
Usage: pull_kernel_artifacts.sh --host <ip-or-name>

Options:
  --host <host>                   Kernel build host to pull artifacts from (required)
  -h, --help                      Show this help message
```

---

### `configure_fastpath_host.sh`

Configures a system to act as a **Fastpath host**.

This script:
- Installs required system packages
- Clones the Arm Fastpath tooling repository

This is used in sections of the Learning Path focused on Fastpath-based kernel testing.

#### Usage

```text
Usage: configure_fastpath_host.sh --host <ip-or-name>

Options:
  --host <host>                   Target Fastpath host (required)
  -h, --help                      Show this help message
```

---

### `configure_fastpath_sut.sh`

Configures a system as a **Fastpath System Under Test (SUT)**.

This script:
- Prepares a target machine for Fastpath testing
- Configures required users and permissions

#### Usage

```text
Usage: configure_fastpath_sut.sh --host <ip-or-name>

Options:
  --host <host>                   Target system under test (SUT) (required)
  -h, --help                      Show this help message
```

---

### `generate_plan.sh`

Generates test plans based on selected kernel builds.

This script:
- Uses the YAML template under `plans/` to interactively generates Fastpath workload plans

#### Usage

```text
Usage: generate_plan.sh

This script is interactive and will prompt for:
  - SUT private IP address
  - Kernel selection

This is used in sections of the Learning Path focused on Fastpath-based kernel testing.

```


### `plans/speedometer.yaml`

This yaml template is used to generate Fastpath-based workload plans. Only needed if compiling for Fastpath / following the Learning Path.

This is used in sections of the Learning Path focused on Fastpath-based kernel testing.

---
