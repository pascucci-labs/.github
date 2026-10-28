# Shared quality, security and performance automation

This platform adds reusable GitHub Actions checks without replacing existing CI.
Community health files in this repository do not activate workflows elsewhere.
Each adopting repository needs a reviewed caller pinned to a central commit.

## Entry points and execution

| Workflow | Purpose | Events in generated caller |
|---|---|---|
| quality.yml | Existing lint, compilation, formatting and tests | PR, main push, weekly, manual |
| security.yml | Local Semgrep rules, Gitleaks commit/history, Trivy IaC | PR, main push, weekly, manual |
| dependency-audit.yml | Trivy dependency vulnerabilities and OSV | PR, main push, weekly, manual |
| performance.yml | Opt-in Lighthouse CI and k6 | Weekly or manual, default branch only |
| repository-sync.yml | Read-only proposals and consolidated report | Private controller only |
| codeql.yml | Optional public-repository CodeQL | Explicit caller only |
| platform-validation.yml | Platform unit tests, actionlint, Semgrep validation | Central PR and main push |

Callers pass `platform-ref` equal to the full SHA in `uses`; that revision is
checked out separately into `.quality-platform`. Scripts and shared security
rules therefore come from the reviewed central revision, not the PR checkout.
Use `scripts/sync-repositories.py --ref <40-character-published-sha>` to generate
correct callers. No movable `main` refs, unpinned external Actions, inherited
secrets, deployments, PR comments or `pull_request_target` jobs are generated.

## Stack detection and project conventions

`python scripts/detect-stack.py /path/to/repository` discovers manifests across
nested applications. It recognizes Maven, Gradle, Spring Boot, npm/JS/TS,
Angular/React/Svelte, Python/uv, Flutter/Dart, Docker/Compose, Terraform,
GitHub Actions, HTML and CSS. It skips dependency installs, generated build
folders, virtual environments, scanner results, and its own platform checkout.
Symlinks are not followed. Manifest discovery is evidence, not permission to
execute arbitrary deploy scripts. Review fixtures/examples and module boundaries
in every adoption plan.

The quality runner uses existing scripts/configuration. Explicit commands in
`.github/org-quality.json` override automatic application commands. Commands
are argument arrays with repository-relative working directories. They execute
untrusted project code only on ephemeral GitHub-hosted runners, with read-only
repository access and no secrets. General checks remain configurable separately.
`examples/org-quality.json` shows custom quality and performance setup.

* Java: Maven `verify` or Gradle wrapper `check`; explicitly configured Maven
  Checkstyle/SpotBugs/PMD check goals and JaCoCo reports are invoked. Gradle's
  configured Checkstyle/SpotBugs/PMD tasks belong to `check`; configured JaCoCo
  adds `jacocoTestReport`. Plugin versions, Java version and rules remain owned
  by the project. Pin plugins in the project before enabling them. Unconfigured
  plugins are not silently installed with a new standard.
* Node: frozen npm/pnpm/yarn installation at the ancestor lockfile; existing
  typecheck, lint, formatting, CI tests and build scripts. Vitest receives
  `--run`, Jest `--ci --runInBand`. Ambiguous test scripts require an override.
  TypeScript with a tsconfig falls back to local `tsc --noEmit`. ESLint,
  Prettier, HTML/CSS, Angular and Svelte checks use existing project scripts.
  pnpm/yarn require an exact `packageManager` declaration; project build
  scripts must not publish/deploy. Workspace installs are deduplicated.
* Python: frozen uv installation with the existing dev extra/group. Declared
  Ruff, configured mypy and declared pytest run; coverage is generated when
  pytest-cov is already declared. Legacy pip installs need explicit commands.
  The runner does not rewrite uv.lock or add lint rules.
* Flutter/Dart: pinned SDK, enforced pub lock, analyze, format check and tests;
  Flutter exports coverage. Override commands when a different SDK is required.
* General: EditorConfig when present; YAML/Markdown only when configuration
  exists; Actionlint for root Actions workflows. No new lint standard is imposed.

Missing tools or failing commands fail the quality job. Manual configuration
notes produce an `incomplete` report rather than a false passing report; they
are informational. Coverage is read from existing coverage.py JSON and Istanbul
summary output when available. Existing CI coverage gates are preserved. Java
and Flutter raw coverage artifacts remain project-owned unless explicitly
exported to a supported summary; unsupported metrics are shown as unknown.
Formatting is enforced only for commands enabled by the repository. To make it
informational initially, omit the format command from the override and keep its
existing advisory workflow. Do not weaken compilation/unit test checks.

## Security policy and baseline

All tools are free CLIs; no Semgrep account or paid Code Security is needed.
Release binaries are SHA-256 checked against `config/tools.json`. Python/npm
CLI packages are version-pinned; their transitive dependency resolution still
uses the upstream registries. Updating these tools is a reviewed maintenance
operation. Renovate handles manifests, Actions and presets; the custom binary
checksum lock needs periodic explicit release/hash verification.

Semgrep runs the original local rules in `config/semgrep`, with metrics disabled.
The initial rule set is intentionally small: Python eval of console input,
JavaScript eval of request fields, and obsolete Java TLS selection. It is not
comprehensive OWASP coverage; expand it with reviewed local rules and fixtures.
Inline nosem suppression is disabled. A scanner error is an incomplete failed
check, not an absence of findings.

Gitleaks scans only base..head commits for a PR, and repository history on main,
schedules and manual runs. Fetch depth is zero. It uses upstream default rules,
central config, full redaction and a distinct findings exit code. Sanitized
history findings include their original commit and native fingerprint so a
moved/deleted file can still be investigated. Source
snippets, matches and secret values never enter published reports. Raw scanner
stdout/stderr is captured and discarded; temporary raw JSON is deleted.
The scan targets `.git` and disables inline allow comments. Exact historical
false positives can be documented in the standard root `.gitleaksignore`: each
entry requires its complete commit:file:rule:line fingerprint and an explanatory
comment. Wildcards, path-only/rule-only entries, duplicates, symlinks and missing
reasons fail closed. PR jobs read that file from the trusted **base commit**,
never the PR head. Default-branch pushes/schedules/manual runs use their
triggering commit; feature-branch manual runs use the fetched default branch
instead, so they cannot approve their own exceptions through another event.
Untracked/modified working-tree ignore files are never used. Each listed commit
must be an ancestor of the trusted revision; a policy cannot pre-authorize a
credential on an unmerged branch. The normalized
report records the trusted revision and exception fingerprints.

Use this only for inspected test fixtures or non-secret prose. An exception
requires review in the repository PR. It is not a waiver for an actual credential
or an ordinary debt baseline. The exact old occurrence is exempted; copying the
same text into a new commit produces a different fingerprint and still fails.
A PR cannot approve a new exception for its own secret. Keep real credentials
blocking and rotate them through the owner's authorized credential process. A fresh
history finding may require credential rotation and remediation; do not hide it.

Trivy scans dependency vulnerabilities, Docker configuration and Terraform/IaC;
optional container images must be explicitly configured by immutable digest.
It never builds/runs a container and requires no Docker socket. OSV runs where
supported dependency files exist, uses a neutral config and supplies aliases,
packages and available fixes. Trivy also receives a neutral ignore file.
Vulnerability databases/API access require internet, but scanner rules and
credentials do not require a paid service. Outages fail analysis explicitly.
Normalized reports deduplicate dependency CVEs by package/version/manifest;
alias differences and differing manifest locations can still produce duplicates.

| Finding | Policy |
|---|---|
| Critical vulnerability | Always fail, including debt |
| Secret | Always fail; no baseline waiver |
| High with fixed version / confirmed local security rule | Fail unless covered by reviewed, unexpired debt baseline |
| High with no actionable fix or confirmation | Report for triage |
| Medium/low/unknown | Report initially |
| Scanner failure | Fail, mark incomplete |
| Compilation / unit failure | Fail |
| Performance regression | Repository-configurable; report initially |

`.github/quality-baseline.json` contains stable finding IDs, a reason with
remediation reference, and ISO expiry date. See the example; copy real IDs from
a sanitized report after review. Baselines are checked in and code-reviewed,
never generated/approved automatically. Critical findings and secrets cannot be
baselined. They remain visible and blocking. Stable IDs can change when a
finding moves line or a dependency version changes; review the new occurrence.

CodeQL is opt-in on public repositories only. Add a caller to `codeql.yml` with
supported detected `languages` (e.g. `javascript-typescript,python`) and grant
`security-events: write` to that job. The initial workflow uses `build-mode:
none`; compiled languages needing a build require a repository-specific build
workflow. Do not infer private eligibility from Team membership. No paid private
feature or repository setting is enabled here. JSON artifacts are the universal
report path; SARIF uploads are not required.

## Dependency updates

`config/renovate.json` is the shared preset: supported Renovate managers cover
Maven/Gradle, npm, Python, pub, Docker and GitHub Actions. Nonmajor updates are
grouped, majors remain separate, at most three concurrent PRs and two per hour,
Monday morning Vancouver time. Vulnerability alerts have higher priority and
can run outside the weekly window when the hosting platform supplies them.
All automerge is disabled by default, including major and security updates.

Install/authorize the free hosted Renovate App only after owner approval. It
needs access to the selected repositories and may send code/dependency metadata
to its hosted service. A self-hosted Renovate process is an alternative with
more operational maintenance. Neither is installed by these workflows.
Existing Dependabot/Renovate configs, including suspicious nested configs,
trigger manual review instead of another dependency bot. The sync script never
disables Dependabot. Resolve nested/inactive configs explicitly.

Optional low-risk automerge should be a separate reviewed repository override
limited to dev-only patches/digests, using PR automerge and protected required
checks. Confirm the branch rule actually requires quality/security/tests and
rejects bypasses before enabling it. Never enable it for major updates or use
`ignoreTests`; the platform does not change branch protections.

## Performance targets

Copy/adapt `examples/lighthouserc.cjs` and `examples/k6-smoke.js`. Configure the
repository's install/build argument arrays, local start command, URL and test
paths. Lighthouse checks performance/accessibility/SEO/best practices budgets;
k6 checks p95 latency and error-rate thresholds. No target means no test.
The workflow only executes on the default branch outside pull requests.
Readiness checks refuse redirects. External targets are denied unless a human
manually dispatches a caller that passes `authorize-external: true` for the
specific reviewed target. Scheduled tests have no such authorization. Never
point load tests at production by default. Test scripts/configurations are
trusted default-branch code; arbitrary scripts can make arbitrary network
requests, so this URL guard is not a network sandbox. Review them before enabling
an external target. Credentials are never inherited. Start processes are stopped
on completion; the hosted VM is discarded after cancellation.

## Organization discovery, review and rollout

1. Publish and review the central change first, preserving existing community
   files. Merge only with owner approval. Record the published immutable commit.
2. Generate a pilot plan from a local central checkout:
   `python scripts/sync-repositories.py --ref <sha> --repo spec-engine --plan pilot-plan.json --dry-run`.
   Read every proposed file and manual note, and retain its printed digest.
3. Apply only the approved exact plan with an authorized short-lived codev App
   installation credential in `GH_TOKEN`, and `--apply --reviewed-digest <digest>`.
   Token acquisition is the owner's existing approved credential path; never
   print it or fall back to the owner's session. The local agent workflow-write
   policy may still require owner publication, regardless of live App scopes.
4. Apply creates a feature branch and draft PR, never a default branch push.
   Trees are additions only; existing workflow/config paths are refused. Changes
   to the default base SHA expire the plan. Plans expire after seven days.
   Existing open adoption PRs are reported without another write. A leftover
   branch with no PR fails safely; inspect it rather than force-update/delete.
5. Merge the pilot after quality/security/test evidence and human review. Run a
   manual main-branch scan as well as a PR. Inspect report artifacts, verify an
   intentional fixture failure in an isolated test repo, measure runtime, and
   confirm fork PRs receive checks without secrets. No broad rollout before this.
6. Generate a new plan for remaining repos, review their existing CI and manual
   requirements, and approve exact per-repository changes. No organization-wide
   modifications are authorized by running discovery.
7. Add a private controller caller to `repository-sync.yml` on a weekly schedule
   or manual dispatch. Pass only an organization-wide read credential explicitly.
   A newly created repo is discovered on the next run and gets a proposal, not
   an automatic mutation. Webhooks are optional future work, not required.
8. Optional Renovate App and Project permissions are separate owner decisions.

`--dry-run` is the default and performs no GitHub writes. Discovery paginates
repositories and rejects truncated trees. Archived/disabled repos are skipped;
empty/inaccessible repos are reported for manual configuration. An existing
caller is considered adopted, not automatically rewritten: immutable-version
upgrades need another reviewed PR. Discovery outputs contain private names and
must not be committed to this public central repository.

## Private reporting and optional Projects

Run `report-results.py` from a PRIVATE controller with read-only org/repository
metadata and Actions access. The report collects artifacts only from main-branch
push/scheduled/manual organization-quality runs. PR artifacts never drive
privileged automation. It tracks scanned/passing/failing/missing/stale states,
critical/high and dependency findings, existing coverage, performance regressions
and last successful scan. Expired/inaccessible/missing results remain unknown.
Outdated package counts are currently unavailable: use the Renovate Dependency
Dashboard until a package-level feed is integrated; this is explicitly shown as
unknown instead of inferred from a vulnerability count. The report separately
lists pending Renovate/Dependabot PRs as actionable update evidence. No dashboard is published
to Pages. Artifacts remain in the private controller with seven-day retention.

`sync-issues.py report.json` produces an issue proposal without writes.
`--apply --reviewed-digest <report-sha256>` is optional and needs explicit owner
authorization and a separate short-lived App credential with issues write.
Only blocking critical/high/secret findings from complete scans are tracked.
Stable markers prevent duplicate issues; complete scans can close resolved
issues, incomplete/stale scans cannot. Minor lint warnings never create issues.
An optional `--project-id <Projects-v2-node-id>` adds issues through GraphQL;
this requires separate approved organization Projects write permission, absent
from the default read-only workflows. Three consecutive completed default-branch quality job failures also produce
a single stable tracking issue for persistent build/test/quality failures. A
subsequent passing quality report resolves it. A transient failure neither
creates nor resolves that issue. One-off quality regressions remain manual triage.

## Cost and isolation

Team currently includes 3,000 monthly private Actions minutes and 2 GB artifact
storage shared with Packages. Standard public Actions runs are free. Source:
https://docs.github.com/en/billing/concepts/product-billing/github-actions
No billing, budgets, Apps, secrets or settings are changed by this implementation.
Actual remaining quota must be checked by the owner; included allowance is not
an assurance of zero cost. Before rollout review an enforced zero-overage budget.

Use Ubuntu standard runners, PR cancellation, bounded job timeouts, seven-day
artifacts and weekly heavy tests. Start with a small number of jobs to amortize
setup. Lock-keyed dependency caches can be added after pilot timing, using only
read-only shared data and no secrets. Changed-path filtering is deliberately not
used for required checks until each monorepo's shared dependencies are mapped;
skipping a workflow can leave a required check pending or miss a shared change.
Do not multiply every language/package into a matrix by default. Measure pilot
minutes and multiply by PR/main/scheduled run counts before expanding.

A Windows 11/4090 host adds no benefit for ordinary lint/scanning. If later used,
run trusted jobs in disposable Linux VMs, no host Docker socket/mounts, no LAN
production access or host credentials, and destroy VM disks per job. Never send
untrusted PR code to a persistent self-hosted runner. Electricity, patching,
virtualization and monitoring are ongoing costs even when Actions minutes are
free. Keep all initial jobs on ephemeral GitHub runners.

## Local validation and maintenance

Run `python -m unittest discover -s tests -v`, `actionlint`, and
`semgrep scan --validate --config config/semgrep --metrics=off`. The central
validation workflow runs these on Linux. Unit tests cover monorepos, paths,
secret redaction, baselines, scanner errors, target authorization, idempotency,
stale/digest-bound plans and issue-resolution safety. This does not replace a
live pilot run. Scanners need network/database validation in that pilot.
Review tool versions/checksums and local rule fixtures periodically, preferably
monthly alongside Renovate updates. Rollback by reverting the adopting caller
PR; existing CI remains intact. Do not delete old artifacts as remediation.
