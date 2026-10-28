#!/usr/bin/env python3
"""Discover repositories and produce exact, reviewable adoption plans; dry-run by default."""
import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

from common import load_script

ORG = 'pascucci-labs'
BRANCH = 'automation/org-quality-v1'


def api(endpoint, method='GET', payload=None):
    argv = ['gh', 'api', endpoint, '--method', method]
    if payload is not None:
        argv += ['--input', '-']
    result = subprocess.run(argv, input=json.dumps(payload) if payload is not None else None,
                            text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(f'GitHub {method} {endpoint}: request failed (exit {result.returncode})')
    return json.loads(result.stdout) if result.stdout.strip() else None


def pages(endpoint):
    items = []
    page = 1
    while True:
        separator = '&' if '?' in endpoint else '?'
        batch = api(f'{endpoint}{separator}per_page=100&page={page}')
        items.extend(batch)
        if len(batch) < 100:
            return items
        page += 1


def caller(ref):
    if not re.fullmatch('[0-9a-f]{40}', ref):
        raise ValueError('Central ref must be a full commit SHA')
    return f'''# Managed by pascucci-labs/.github; changes require review.
name: Organization quality
on:
  pull_request:
  push:
    branches: [$default-branch$]
  schedule:
    - cron: '23 6 * * 1'
  workflow_dispatch:
permissions:
  contents: read
concurrency:
  group: org-quality-${{{{ github.workflow }}}}-${{{{ github.ref }}}}
  cancel-in-progress: ${{{{ github.event_name == 'pull_request' }}}}
jobs:
  quality:
    uses: pascucci-labs/.github/.github/workflows/quality.yml@{ref}
    with:
      platform-ref: {ref}
  security:
    uses: pascucci-labs/.github/.github/workflows/security.yml@{ref}
    with:
      platform-ref: {ref}
  dependencies:
    uses: pascucci-labs/.github/.github/workflows/dependency-audit.yml@{ref}
    with:
      platform-ref: {ref}
  performance:
    if: github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'
    uses: pascucci-labs/.github/.github/workflows/performance.yml@{ref}
    with:
      platform-ref: {ref}
'''


def propose(repo, paths, ref, read):
    scan = load_script('detect-stack').detect(paths, read)
    result = {'repository': repo['full_name'], 'base': repo['base'], 'branch': repo['default_branch'],
              'private': repo['private'], 'stack': scan, 'files': {}, 'manual': []}
    if repo.get('archived') or repo.get('disabled'):
        result['state'] = 'archived' if repo.get('archived') else 'disabled'
        return result
    if repo['name'] == '.github':
        result['state'] = 'central'
        return result
    if '.github/workflows/org-quality.yml' in paths:
        result['state'] = 'adopted'
        return result
    result['state'] = 'proposed'
    # JSON quoting is YAML-safe for arbitrary default branch names.
    result['files']['.github/workflows/org-quality.yml'] = caller(ref).replace('$default-branch$', json.dumps(repo['default_branch']))
    existing = '.github/org-quality.json'
    if existing not in paths:
        config = {'quality': {'general': True}}
        if scan['workflows']:
            config['quality']['commands'] = []
            result['manual'].append('Existing CI retained; only general quality checks added. Review coverage of existing jobs.')
        result['files'][existing] = json.dumps(config, indent=2) + '\n'
    if scan['dependency_configs']:
        result['manual'].append('Existing dependency automation found; Renovate not added: ' + ', '.join(scan['dependency_configs']))
    else:
        result['files']['.github/renovate.json'] = json.dumps({'extends': [f'github>pascucci-labs/.github//config/renovate#{ref}']}, indent=2) + '\n'
    if not scan['modules']:
        result['manual'].append('No supported application manifest; general/security checks only')
    return result


def digest(plan):
    return hashlib.sha256(json.dumps(plan, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def discover(ref, names=None):
    # Confirm central commit and workflow files exist before proposing callers.
    for workflow in ('quality', 'security', 'dependency-audit', 'performance'):
        api(f'repos/{ORG}/.github/contents/.github/workflows/{workflow}.yml?ref={ref}')
    entries = []
    for repo in pages(f'orgs/{ORG}/repos'):
        if names and repo['name'] not in names:
            continue
        if repo['archived'] or repo['disabled']:
            entries.append({'repository': repo['full_name'], 'state': 'archived' if repo['archived'] else 'disabled', 'files': {}})
            continue
        try:
            base = api(f"repos/{repo['full_name']}/commits/{repo['default_branch']}")['sha']
            tree = api(f"repos/{repo['full_name']}/git/trees/{base}?recursive=1")
            if tree.get('truncated'):
                raise ValueError('Truncated tree; manual inspection required')
            paths = [p['path'] for p in tree['tree'] if p['type'] == 'blob']
            def read(path):
                file = api(f"repos/{repo['full_name']}/contents/{path}?ref={base}")
                return base64.b64decode(file['content']).decode(errors='replace')
            entries.append(propose(repo | {'base': base}, paths, ref, read))
        except (RuntimeError, ValueError, KeyError):
            entries.append({'repository': repo['full_name'], 'state': 'manual', 'files': {}, 'manual': ['Discovery failed or repository empty; no changes proposed']})
    return {'schema': 1, 'organization': ORG, 'central_ref': ref, 'created': dt.datetime.now(dt.timezone.utc).isoformat(), 'repositories': entries}


def apply(plan, reviewed_digest):
    if digest(plan) != reviewed_digest:
        raise ValueError('Reviewed digest does not match exact plan')
    if plan.get('schema') != 1 or plan.get('organization') != ORG:
        raise ValueError('Unexpected plan schema/organization')
    # Cross-repository writes require the deliberately supplied bot credential.
    # Never fall back to the human gh session or GITHUB_TOKEN.
    if not os.environ.get('GH_TOKEN', '').startswith('ghs_'):
        raise ValueError('Apply requires an explicit short-lived GitHub App installation GH_TOKEN')
    age = dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(plan['created'])
    if age.total_seconds() < 0 or age > dt.timedelta(days=7):
        raise ValueError('Plan expired; regenerate and review')
    for entry in plan['repositories']:
        if entry['state'] != 'proposed':
            continue
        repo = entry['repository']
        if not re.fullmatch(r'pascucci-labs/[A-Za-z0-9_.-]+', repo):
            raise ValueError('Repository outside organization')
        existing = api(f'repos/{repo}/pulls?state=open&head={ORG}:{BRANCH}')
        if existing:
            print(f'{repo}: existing PR {existing[0]["html_url"]}; no mutation')
            continue
        metadata = api(f'repos/{repo}')
        if metadata['archived'] or metadata['disabled']:
            raise ValueError('Repository is no longer active')
        current = api(f"repos/{repo}/commits/{entry['branch']}")
        if current['sha'] != entry['base']:
            raise ValueError(f'{repo}: default branch changed; regenerate plan')
        tree = api(f'repos/{repo}/git/trees/{entry["base"]}?recursive=1')
        if tree.get('truncated'):
            raise ValueError('Truncated tree')
        paths = {p['path'] for p in tree['tree']}
        allowed = {'.github/workflows/org-quality.yml', '.github/org-quality.json', '.github/renovate.json'}
        if not set(entry['files']) <= allowed or paths.intersection(entry['files']):
            raise ValueError('Plan would overwrite existing files or create unexpected paths')
        nodes = [{'path': path, 'mode': '100644', 'type': 'blob', 'content': content} for path, content in entry['files'].items()]
        new_tree = api(f'repos/{repo}/git/trees', 'POST', {'base_tree': current['commit']['tree']['sha'], 'tree': nodes})
        commit = api(f'repos/{repo}/git/commits', 'POST', {'message': 'Add shared organization quality checks', 'tree': new_tree['sha'], 'parents': [entry['base']],
                     'author': {'name': 'pascucci-labs-codev[bot]', 'email': 'pascucci-labs-codev[bot]@users.noreply.github.com'}})
        # Creating an existing branch fails; never force-update an abandoned branch.
        api(f'repos/{repo}/git/refs', 'POST', {'ref': f'refs/heads/{BRANCH}', 'sha': commit['sha']})
        body = 'Adds reviewed callers for central quality/security/dependency checks. Existing CI and deployment files are preserved.\n\nCI workflow changes: adds `.github/workflows/org-quality.yml`. No inherited secrets; GitHub-hosted runners only.\n\nReviewed plan: `' + reviewed_digest + '`\n\n' + '\n'.join('- ' + n for n in entry['manual'])
        pr = api(f'repos/{repo}/pulls', 'POST', {'title': 'Adopt shared organization quality automation', 'head': BRANCH, 'base': entry['branch'], 'body': body, 'draft': True})
        print(pr['html_url'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ref', help='Published central commit SHA')
    parser.add_argument('--repo', action='append', help='Optional repository name allowlist')
    parser.add_argument('--plan', type=Path, default=Path('repository-plan.json'))
    parser.add_argument('--dry-run', action='store_true', help='Default: discover and write plan only')
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--reviewed-digest')
    args = parser.parse_args()
    if args.apply:
        if args.dry_run or not args.reviewed_digest:
            parser.error('Apply requires --reviewed-digest and cannot use --dry-run')
        apply(json.loads(args.plan.read_text()), args.reviewed_digest)
    else:
        if not args.ref:
            parser.error('--ref is required for discovery')
        plan = discover(args.ref, args.repo)
        if args.plan.exists():
            raise SystemExit('Plan already exists; choose a new path to preserve reviewed evidence')
        args.plan.write_text(json.dumps(plan, indent=2) + '\n')
        print('Review the complete proposed files in', args.plan, '\nDigest:', digest(plan))
