# Security Policy

`why-slow` is engineered from the ground up for mission-critical enterprise, cloud-native, and banking environments (PCI-DSS v4.0 and SOC 2 Type II compliant). We take security, zero-write safety, and virtual filesystem integrity with utmost seriousness.

---

## Supported Versions

We provide security updates and critical patches for the following versions:

| Version | Supported          | Security Maintenance Window |
| ------- | ------------------ | --------------------------- |
| 0.26.x  | :white_check_mark: | Current stable release line |
| < 0.26  | :x:                | Deprecated                  |

We strongly advise all operators and contributors to keep their installations on the latest release tag.

---

## Core Security Invariants (Non-Negotiable)

`why-slow` enforces strict architectural security invariants that must never be bypassed:

1. **Strict Read-Only Access (`O_RDONLY`)**:
   - All interactions with the host filesystem, specifically `/proc`, `/sys`, and device nodes, are opened strictly with `syscall.O_RDONLY`.
   - The engine performs **zero write operations**, creates **zero temporary files** in `/tmp` or `/dev/shm`, and executes **zero state-altering ioctl calls**.
2. **Zero Elevated Syscall Requirement (Opportunistic Elevation)**:
   - The tool never requires `sudo` or elevated privileges. It runs cleanly as an unprivileged user with silent, graceful degradation when kernel entries are restricted.
   - Elevation (`sudo why-slow`) merely widens unprivileged read boundaries (e.g. `/proc/[pid]/io` visibility across all host users). It uses **zero setuid binaries**, **zero ambient capabilities (`CAP_*`)**, and **zero privilege-dropping mechanisms**.
3. **Zero External Dependencies & Zero CGo**:
   - Built 100% with the Go standard library (`CGO_ENABLED=0`).
   - Third-party packages and external CLI wrapping (`exec.Command` invoking `ps`, `lsof`, or `iostat`) are strictly prohibited, eliminating supply-chain attack vectors.
4. **Zero Sensitive Path Access**:
   - Never reads or parses sensitive paths including `/proc/[pid]/environ`, `/proc/[pid]/mem`, `/proc/[pid]/maps`, `/proc/kcore`, or private cryptographic key files.
   - Operates safely in multi-tenant environments under `hidepid=2` mount protections.
5. **Zero Outbound Telemetry / Zero Network Usage**:
   - The binary does not listen on any network socket, make HTTP requests, or emit outbound telemetry. Telemetry never leaves the host unless piped explicitly by the operator.

---

## Automated CI/CD Anti-Backdoor Gates

Every Pull Request submitted to `why-slow` must pass automated, deterministic security gate checks in GitHub Actions before any code can be merged:

1. **Supply-Chain Gate**: Asserts that `go.mod` contains strictly **zero third-party dependencies**.
2. **Anti-Backdoor Gate**: Scans all production code to assert **zero `exec.Command` or `os.StartProcess`** invocations.
3. **Read-Only Gate**: Asserts **zero `os.Create`, `os.WriteFile`, `os.Remove`**, or filesystem write operations in production code.
4. **Anti-Exfiltration Gate**: Asserts **zero `net.Dial` or HTTP clients** preventing any remote telemetry transmission.
5. **Sensitive Path Gate**: Asserts **zero access to `/proc/[pid]/environ`, `/proc/[pid]/maps`**, or credential files.
6. **Go Vulnerability Database**: Scans all code using the official Go vulnerability database (`govulncheck`).

---

## Reporting a Vulnerability

If you discover a security vulnerability or a potential invariant bypass in `why-slow`:

### 1. Preferred Method: GitHub Private Vulnerability Reporting
Please submit a report through GitHub's [Private Vulnerability Reporting](https://github.com/cetinkayaismail/why-slow/security/advisories/new) interface. This keeps the vulnerability private while maintainers investigate and prepare a patch.

### 2. Alternative Method: Direct Security Contact
If you cannot use GitHub Security Advisories, send an encrypted or direct email to the project maintainer:
- **Email**: `cetinkayaismail.dev@gmail.com`
- **Subject**: `[SECURITY] why-slow: Potential vulnerability in <component>`

Please include the following details:
- A description of the vulnerability and its potential impact.
- Affected versions, Linux distribution, and kernel version (`uname -r`).
- Step-by-step reproduction instructions or a minimal Proof of Concept (PoC).
- Any proposed remediation or mitigation.

---

## Vulnerability Handling Timeline

- **Initial Acknowledgment**: Within 24 hours of receiving the disclosure.
- **Triage & Reproduction**: Within 48 hours.
- **Fix & Verification**: Within 7 business days for critical findings.
- **Public Disclosure**: Coordinated disclosure after a patched release is published and operators have been given a reasonable upgrade window.

---

## Hall of Fame & Responsible Disclosure

We sincerely appreciate the efforts of security researchers who help protect the open-source community. If you report a valid, previously undisclosed security vulnerability adhering to responsible disclosure practices, we will proudly credit your contribution in our release notes and Security Hall of Fame.
