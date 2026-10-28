#!/usr/bin/env python3
"""Optional, reviewed issue reconciliation from trusted report artifacts; dry-run first."""
import argparse
import hashlib
import json
from pathlib import Path

from common import load_script

sync = load_script('sync-repositories')


def desired(report):
    result = []
    for row in report['repositories']:
        # Unknown/failed scanners must never resolve existing tracking issues.
        trusted = row.get('results', {})
        if not row.get('run') or row.get('state') not in {'success', 'failure'}:
            continue
        if row.get('persistent_quality_failure'):
            result.append({'repository': row['repository'], 'kind': 'quality', 'run': row['run'], 'findings': [{'id': 'persistent-quality-failure', 'severity': 'HIGH', 'rule': 'Three consecutive default-branch quality failures', 'path': '', 'package': '', 'fixed': 'Repair the failing compilation/test/quality commands'}]})
        elif trusted.get('quality', {}).get('status') == 'passed':
            result.append({'repository': row['repository'], 'kind': 'quality', 'run': row['run'], 'findings': []})
        for kind in ('security', 'dependencies'):
            scan = trusted.get(kind, {})
            if not scan.get('complete'):
                continue
            current = {f['id']: f for f in scan.get('findings', []) if f.get('blocking')}
            result.append({'repository': row['repository'], 'kind': kind, 'findings': list(current.values()), 'run': row['run']})
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', type=Path)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--reviewed-digest')
    parser.add_argument('--project-id', help='Optional Projects v2 node ID; requires separate authorized project permission')
    args = parser.parse_args()
    raw = args.report.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    proposals = desired(json.loads(raw))
    if not args.apply:
        print(json.dumps(proposals, indent=2))
        print('Report digest:', digest)
        raise SystemExit(0)
    if args.reviewed_digest != digest:
        raise SystemExit('Exact reviewed report digest required')
    import os
    if not os.environ.get('GH_TOKEN', '').startswith('ghs_'):
        raise SystemExit('Supply the explicitly authorized short-lived App GH_TOKEN')
    for group in proposals:
        repo = group['repository']
        if not repo.startswith('pascucci-labs/'):
            raise ValueError('Unexpected repository')
        prefix = f'<!-- org-quality:{group["kind"]}:'
        issues = sync.pages(f'repos/{repo}/issues?state=all')
        managed = {issue['body'].split(prefix, 1)[1].split(' -->', 1)[0]: issue for issue in issues if not issue.get('pull_request') and prefix in (issue.get('body') or '')}
        current = {f['id'] for f in group['findings']}
        for item in group['findings']:
            marker = prefix + item['id'] + ' -->'
            body = marker + '\n\nBlocking ' + item['severity'] + ' finding.\n\nDetails: ' + group['run'] + '\n\nRule: `' + item['rule'] + '`\nFile: `' + item['path'] + '`\nPackage: `' + item['package'] + '`\nAvailable fixes: `' + item['fixed'] + '`'
            payload = {'title': f'Quality automation: {item["severity"]} {item["rule"]}', 'body': body, 'state': 'open'}
            existing = managed.get(item['id'])
            issue = sync.api(f'repos/{repo}/issues/{existing["number"]}', 'PATCH', payload) if existing else sync.api(f'repos/{repo}/issues', 'POST', {k: v for k, v in payload.items() if k != 'state'})
            if args.project_id:
                query = 'mutation($project:ID!,$content:ID!){addProjectV2ItemById(input:{projectId:$project,contentId:$content}){item{id}}}'
                response = sync.api('graphql', 'POST', {'query': query, 'variables': {'project': args.project_id, 'content': issue['node_id']}})
                if response.get('errors'):
                    raise RuntimeError('Project update failed; check approved Project permissions')
        for identifier, issue in managed.items():
            if identifier not in current and issue['state'] == 'open':
                sync.api(f'repos/{repo}/issues/{issue["number"]}', 'PATCH', {'state': 'closed', 'state_reason': 'completed'})
