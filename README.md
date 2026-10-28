# `.github` — org defaults for Pascucci Labs

GitHub falls back to this repository for community health files that a given
repository does not define itself. Anything here becomes the org-wide default;
any repository can still override it by shipping its own copy.

| Path | Applies to |
|---|---|
| `.github/CODEOWNERS` | Default reviewers where a repo defines none |
| `.github/pull_request_template.md` | Default PR body across the org |
| `.github/ISSUE_TEMPLATE/` | Default issue forms |
| `AGENTS.md` | Pointer to the shared agent configuration |
| `profile/README.md` | Public org landing page |

## Agent configuration

The substance lives in [`pascucci-labs/spec-engine` `.agents/`](https://github.com/pascucci-labs/spec-engine/tree/main/.agents),
not here. This repository only points at it, so there is one source of truth:

- `.agents/global/AGENTS.md` — shared working style and shell conventions
- `.agents/policies/agent-scope.md` — what agents may do unattended
- `.agents/policies/identity.md` — how agent identities authenticate
- `.agents/policies/rulesets/` — org branch rules, as version-controlled JSON

## Note on scope

Community health fallback covers `CODEOWNERS`, issue and PR templates,
`CONTRIBUTING`, `SECURITY`, and similar. It does **not** distribute workflows,
settings, or agent instruction files into other repositories — those still have
to be committed per repository, or installed locally by `spec-engine/.agents/install.sh`.
