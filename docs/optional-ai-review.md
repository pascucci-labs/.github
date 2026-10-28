# Optional Kodus evaluation

Kodus is an advisory AI review layer alongside deterministic checks. It is not
installed by this platform and is not required for merges. Evaluate it on the
pilot first; track actionable findings, false positives, review latency and
operator time over representative agent-authored PRs before enabling more repos.

As checked 2026-10-28, Community is free with unlimited users/PRs, up to ten
custom rules and three active plugins. Hosted model API tokens cost extra;
self-hosted inference avoids that external token bill. Teams is $10 per developer
per month plus tokens (annual discount available). The core is AGPLv3; enterprise
components have separate license terms. Confirm current terms at installation.

Sources:
- https://kodus.io/pricing/
- https://github.com/kodustech/kodus-ai
- https://github.com/kodustech/kodus-ai/blob/main/license_ee.md
- https://github.com/kodustech/kodus-installer/blob/main/docker-compose.yml
- https://kodus.io/self-hosted-ai-code-review/

Use a dedicated x86 Linux host/VM if the owner chooses to proceed. Published
starting requirements are two CPU cores, 8 GB RAM and 60 GB storage; 16 GB and
an SSD are a practical recommendation, not a measured requirement. No GPU is
needed on the application host when inference is remote. The current standard
Compose installer explicitly selects amd64 for several core services. An ARM
host would require additional image/build validation and ongoing maintenance.

The owner is looking for a suitable x86 machine. Deployment location and model
remain undecided. A local Ollama endpoint can provide inference; run one review
at a time initially and test accuracy/context limits before relying on it.
Private LAN endpoint addresses, host details and credentials belong in private
platform configuration, not this public repository. Do not expose an unauthenticated
Ollama API to the internet. GitHub webhook ingress, app permissions, network
routes, credentials and service deployment require explicit separate approval.
AI output cannot authorize merges, execute PR-supplied commands or waive critical
scanner findings. Keep the initial integration advisory and avoid duplicate
comments alongside other existing AI reviewers.
