# Agent Instructions — Pascucci Labs

This is the organization defaults repository. It holds no application code.

The shared agent configuration lives in
[`pascucci-labs/spec-engine` `.agents/`](https://github.com/pascucci-labs/spec-engine/tree/main/.agents). Read it
before working in any repository in this organization:

- `global/AGENTS.md` — working style, shell conventions, context detection
- `policies/agent-scope.md` — green / yellow / red action classification
- `policies/identity.md` — agent authentication and permission ceilings

A repository-local `AGENTS.md` or `CLAUDE.md` always takes precedence over these
shared defaults.

## Working in this repository specifically

Changes here alter defaults across every repository in the organization. Treat
that as an amber action: land it through a pull request with the blast radius
stated in the body, never as a direct push.
