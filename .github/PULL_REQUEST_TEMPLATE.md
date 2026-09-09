## 📝 Description

Please provide a clear and concise description of the changes proposed in this Pull Request.
Explain the motivation, problem solved, or kernel metric introduced.

Related Issue: Fixes # <!-- issue number, if applicable -->

---

## 🏛️ Invariant & Architectural Verification

Every contribution must strictly preserve our core invariants. Please confirm the following:

- [ ] **Zero Dependencies**: No third-party modules were added to `go.mod` (pure Go standard library only).
- [ ] **Zero CGo**: Builds cleanly with `CGO_ENABLED=0`.
- [ ] **Strict Read-Only**: Virtual files in `/proc` and `/sys` are opened with `O_RDONLY`. Zero write operations, zero disk mutations, and zero `/tmp` files created.
- [ ] **Zero Sensitive Access**: No reads of `/proc/[pid]/environ`, `/proc/[pid]/mem`, or private credential files.
- [ ] **Opportunistic Elevation**: Works unprivileged without requiring `sudo` or setuid capabilities.
- [ ] **Function Length**: Functions comply with the $\le 60$ lines guideline.
- [ ] **English Only**: All comments, variable names, and documentation are in English.

---

## 🧪 Testing & Validation

Please indicate which tests were executed locally:

- [ ] `make vet` passed with zero warnings.
- [ ] `make test` (`go test -race -count=1 ./internal/...`) passed cleanly without race conditions.
- [ ] If proposing a new diagnostic rule:
  - [ ] Added positive unit test case in `internal/analyzer/rules_tier*_test.go`.
  - [ ] Added negative baseline unit test case in `internal/analyzer/rules_tier*_test.go`.
  - [ ] Added cross-tier disambiguation test in `internal/analyzer/disambiguation_test.go`.
  - [ ] Documented the rule in `docs/RULES_CATALOG.md`.
- [ ] Updated `docs/CHANGELOG.md` with release notes.
