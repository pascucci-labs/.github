#!/usr/bin/env python3
"""Opt-in trusted-branch Lighthouse/k6 tests. External targets require runtime authorization."""
import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

from common import configuration, safe_path


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError('Readiness URL must not redirect')


def target_allowed(url, external_authorized=False):
    target = urlsplit(url)
    if target.scheme not in {'http', 'https'} or target.username or target.password or not target.hostname:
        raise ValueError('Expected HTTP(S) target without credentials')
    if target.hostname not in {'127.0.0.1', 'localhost', '::1'} and not external_authorized:
        raise ValueError('External target requires explicit workflow_dispatch authorization')
    return url


def main(root, authorized=False):
    root = Path(root).resolve()
    output = root / '.quality-results'
    output.mkdir(exist_ok=True)
    config = configuration(root).get('performance', {})
    document = {'schema': 1, 'kind': 'performance', 'status': 'not-configured', 'results': []}
    app = None
    try:
        if config:
            url = target_allowed(config['url'], authorized)
            for command in config.get('prepare', []):
                if not isinstance(command, list) or not command:
                    raise ValueError('performance.prepare entries must be argument arrays')
                subprocess.run(command, cwd=safe_path(root, config.get('path', '.')), check=True)
            if config.get('start'):
                argv = config['start']
                if not isinstance(argv, list) or not argv:
                    raise ValueError('performance.start must be an argument array')
                app = subprocess.Popen(argv, cwd=safe_path(root, config.get('path', '.')), start_new_session=True)
            opener = urllib.request.build_opener(NoRedirect)
            ready = False
            for _ in range(30):
                try:
                    with opener.open(url, timeout=2) as response:
                        ready = 200 <= response.status < 400
                    if ready:
                        break
                except (OSError, urllib.error.URLError):
                    pass
                time.sleep(1)
            if not ready:
                raise RuntimeError('Configured app did not become ready')
            cwd = safe_path(root, config.get('path', '.'))
            if config.get('lighthouse'):
                settings = safe_path(root, config['lighthouse'])
                # Explicit repo-owned LHCI config owns start server, budgets and categories.
                status = subprocess.run(['lhci', 'autorun', '--config', str(settings), '--collect.url', url], cwd=cwd).returncode
                document['results'].append({'tool': 'lighthouse', 'regression': status != 0})
            if config.get('k6'):
                script = safe_path(root, config['k6'])
                status = subprocess.run(['k6', 'run', '--summary-export', str(output / 'k6-summary.json'), str(script)], cwd=cwd, env=os.environ | {'TARGET_URL': url}).returncode
                document['results'].append({'tool': 'k6', 'regression': status != 0})
            if not document['results']:
                raise ValueError('Configure lighthouse or k6')
            document['status'] = 'regression' if any(r['regression'] for r in document['results']) else 'passed'
    except (ValueError, KeyError, OSError, RuntimeError, subprocess.CalledProcessError):
        document['status'] = 'failed'
        document['error'] = 'Performance target/configuration failed; check local target and tool configuration'
    finally:
        if app:
            import signal
            try:
                os.killpg(app.pid, signal.SIGTERM)
                app.wait(timeout=10)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                if app.poll() is None:
                    os.killpg(app.pid, signal.SIGKILL)
        (output / 'performance.json').write_text(json.dumps(document, indent=2))
    print(json.dumps(document, indent=2))
    blocking = config.get('blocking', False)
    return int(document['status'] == 'failed' or (blocking and document['status'] == 'regression'))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', default='.')
    parser.add_argument('--authorize-external', action='store_true')
    args = parser.parse_args()
    # Authorization is never honored on a PR or automatic schedule.
    if args.authorize_external and os.environ.get('GITHUB_EVENT_NAME') != 'workflow_dispatch':
        raise SystemExit('External authorization requires manual workflow_dispatch')
    sys.exit(main(args.root, args.authorize_external))
