# Local validation evidence — 2026-10-28

- 20 focused unit tests pass, including monorepo/framework detection, symlinks,
  CVSS severity, unwaivable secrets/critical findings, expiry, missing-tool
  reporting, stale plans, pagination, idempotency and incomplete scan safety.
- All central reusable and validation workflows pass Actionlint locally.
- Semgrep 1.182.1 validates all three local rules and detects the unsafe-eval
  fixture with no account.
- Gitleaks 8.30.1 detects a synthetic committed secret using the exact command
  flags, against the git directory with a root ignore file present. Raw output
  and secret values were withheld; no real credential was used.
- Python syntax and Ruff E9/F checks pass.

The central draft PR is https://github.com/pascucci-labs/.github/pull/4 and the
pilot draft is https://github.com/pascucci-labs/spec-engine/pull/230. The first
central Actions validation passed, and the pilot successfully invoked the
published reusable workflows. Source security scanning passed. The dependency
job produced blocking findings, and exposed that upload-artifact excludes hidden
report directories by default. Uploads now explicitly include the dedicated
sanitary report directory; raw scanner files remain outside that directory.
Neither PR is merged. Renovate is not installed, and no settings/credentials,
tracking issues, other repository adoption or deployments were created. Trivy/OSV database access,
Linux binary downloads, cross-repository reusable-workflow calls, full history
scan triage, private reporting access and the optional performance fixtures
still need the live pilot. Do not expand rollout before that evidence exists.

Pilot repository baseline and private organization discovery are kept in the
private pilot change, not in this public repository.

## Historical fixture handling

The follow-up has 27 passing focused tests. These include trusted PR-base
selection, PR-head bypass attempts, working-tree tampering, symlink/missing
Git-object rejection, exact fingerprint validation and retained commit metadata.
A local Gitleaks 8.30.1 full-history scan of the spec-engine fixture-exception
proposal passes with zero findings. A new synthetic secret remains blocking even
when its PR head adds its own fingerprint to the ignore file. No real secret
values are printed, and critical/debt-baseline policy remains unchanged.
