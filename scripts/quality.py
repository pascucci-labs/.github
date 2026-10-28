#!/usr/bin/env python3
"""Run repository-owned standards. No generated linter configuration is imposed."""
import argparse
import json
import os
import subprocess
import sys
import tomllib
from pathlib import Path

from common import configuration, execute, load_script, safe_path


def auto_commands(root, module):
    path = safe_path(root, module['path'])
    kind = module['kind']
    commands = []
    manual = []
    if kind == 'node':
        # A workspace lock owns dependency installation, but child scripts still run.
        owner = path
        while owner != root and not any((owner / n).exists() for n in ('package-lock.json', 'pnpm-lock.yaml', 'yarn.lock')):
            owner = owner.parent
        if (owner / 'pnpm-lock.yaml').exists():
            package = json.loads((owner / 'package.json').read_text())
            manager = package.get('packageManager', '')
            if not manager.startswith('pnpm@'):
                return [], ['Pin packageManager to pnpm@version for frozen installs']
            commands += [(owner, ['corepack', 'enable']), (owner, ['corepack', 'prepare', manager, '--activate']), (owner, ['pnpm', 'install', '--frozen-lockfile'])]
            runner = ['pnpm', 'run']
        elif (owner / 'package-lock.json').exists():
            commands.append((owner, ['npm', 'ci']))
            runner = ['npm', 'run']
        elif (owner / 'yarn.lock').exists():
            package = json.loads((owner / 'package.json').read_text())
            manager = package.get('packageManager', '')
            if not manager.startswith('yarn@'):
                return [], ['Pin packageManager to yarn@version for frozen installs']
            commands += [(owner, ['corepack', 'enable']), (owner, ['corepack', 'prepare', manager, '--activate']), (owner, ['yarn', 'install', '--immutable'] if not manager.startswith('yarn@1.') else ['yarn', 'install', '--frozen-lockfile'])]
            runner = ['yarn', 'run']
        else:
            return [], ['No lockfile; provide explicit quality.commands']
        scripts = module.get('scripts', {})
        for group in (('typecheck', 'check:types'), ('lint',), ('format:check', 'prettier:check'), ('test:ci',), ('build',)):
            selected = next((n for n in group if n in scripts), None)
            if selected:
                commands.append((path, runner + [selected]))
        if 'test:ci' not in scripts and 'test' in scripts:
            test = scripts['test']
            if 'vitest' in test:
                commands.append((path, runner + ['test', '--', '--run']))
            elif 'jest' in test:
                commands.append((path, runner + ['test', '--', '--ci', '--runInBand']))
            else:
                manual.append('Nonstandard test command; configure quality.commands to prevent watch mode')
        if not any(n in scripts for n in ('typecheck', 'check:types')) and list(path.glob('tsconfig*.json')):
            commands.append((path, ['npm', 'exec', '--no', '--', 'tsc', '--noEmit']))
    elif kind == 'python':
        pyproject = path / 'pyproject.toml'
        data = tomllib.loads(pyproject.read_text()) if pyproject.exists() else {}
        if not (path / 'uv.lock').exists():
            return [], ['Python project without uv.lock needs explicit install/check commands']
        sync = ['uv', 'sync', '--frozen']
        if 'dev' in data.get('project', {}).get('optional-dependencies', {}):
            sync += ['--extra', 'dev']
        commands.append((path, sync))
        # Only run tools declared/configured by the repository.
        declared = json.dumps(data).lower()
        for tool, argv in [('ruff', ['ruff', 'check', '.']), ('mypy', ['mypy', '.'])]:
            if tool in declared or (path / f'.{tool}.ini').exists():
                commands.append((path, ['uv', 'run', '--frozen', '--no-sync'] + argv))
        if 'pytest' in declared or (path / 'pytest.ini').exists():
            commands.append((path, ['uv', 'run', '--frozen', '--no-sync', 'pytest', '-q'] + (['--cov=.', '--cov-report=json'] if 'pytest-cov' in declared else [])))
    elif kind == 'java':
        if 'pom.xml' in module['manifests']:
            wrapper = path / 'mvnw'
            commands.append((path, (['bash', './mvnw'] if wrapper.exists() else ['mvn']) + ['--batch-mode', 'verify']))
        elif (path / 'gradlew').exists():
            commands.append((path, ['bash', './gradlew', '--no-daemon', 'check']))
        else:
            manual.append('Gradle needs a checked-in wrapper or explicit commands')
        build_text = '\n'.join((path / name).read_text() for name in module['manifests'])
        if 'pom.xml' in module['manifests']:
            prefix = ['bash', './mvnw'] if (path / 'mvnw').exists() else ['mvn']
            for plugin, goal in [('maven-checkstyle-plugin', 'checkstyle:check'), ('spotbugs-maven-plugin', 'spotbugs:check'), ('maven-pmd-plugin', 'pmd:check'), ('jacoco-maven-plugin', 'jacoco:report')]:
                if plugin in build_text:
                    commands.append((path, prefix + ['--batch-mode', goal]))
        elif 'jacoco' in build_text:
            commands.append((path, ['bash', './gradlew', '--no-daemon', 'jacocoTestReport']))
    elif kind in {'flutter', 'dart'}:
        runner = 'flutter' if kind == 'flutter' else 'dart'
        commands = [(path, [runner, 'pub', 'get', '--enforce-lockfile']), (path, ['dart', 'format', '--output=none', '--set-exit-if-changed', '.']), (path, [runner, 'analyze']), (path, [runner, 'test'] + (['--coverage'] if kind == 'flutter' else []))]
    return commands, manual


def main(root, only=None):
    root = Path(root).resolve()
    config = configuration(root)
    scan = load_script('detect-stack').local(root)
    output = root / '.quality-results'
    output.mkdir(exist_ok=True)
    results = []
    commands = config.get('quality', {}).get('commands')
    tasks = []
    manual = []
    if commands is not None:
        for item in commands:
            tasks.append((safe_path(root, item.get('path', '.')), item['run']))
    else:
        for module in scan['modules']:
            if only is not None and module['path'] != only:
                continue
            found, notes = auto_commands(root, module)
            tasks.extend(found)
            manual.extend(f"{module['path']}: {note}" for note in notes)
    # Deduplicate shared workspace installs, preserve command order.
    seen = set()
    for cwd, argv in tasks:
        if not isinstance(argv, list) or not argv or not all(isinstance(x, str) for x in argv):
            raise ValueError('quality.commands[].run must be an argument array')
        key = (str(cwd), tuple(argv))
        if key in seen:
            continue
        seen.add(key)
        try:
            execute(argv, cwd, env=os.environ | {'CI': 'true'})
            results.append({'path': str(cwd.relative_to(root)), 'command': argv, 'status': 'passed'})
        except (subprocess.CalledProcessError, FileNotFoundError):
            results.append({'path': str(cwd.relative_to(root)), 'command': argv, 'status': 'failed'})
    if config.get('quality', {}).get('general', True):
        general = []
        if '.editorconfig' in [p.name for p in root.iterdir()]:
            general.append(['editorconfig-checker'])
        if any((root / p).exists() for p in ('.yamllint', '.yamllint.yml', '.yamllint.yaml')):
            general.append(['yamllint', '.'])
        if any((root / p).exists() for p in ('.markdownlint.json', '.markdownlint.yaml', '.markdownlint.yml', '.markdownlint-cli2.jsonc')):
            general.append(['markdownlint-cli2', '**/*.md', '#node_modules', '#.quality-platform', '#.venv'])
        if scan['workflows']:
            general.append(['actionlint'] + scan['workflows'])
        for argv in general:
            try:
                execute(argv, root)
                results.append({'command': argv, 'status': 'passed'})
            except (subprocess.CalledProcessError, FileNotFoundError):
                results.append({'command': argv, 'status': 'failed'})
    coverage = {}
    for module in scan['modules']:
        base = safe_path(root, module['path'])
        for name in ('coverage.json', 'coverage/coverage-summary.json'):
            file = base / name
            if file.is_file() and not file.is_symlink():
                try:
                    data = json.loads(file.read_text())
                    pct = data.get('totals', {}).get('percent_covered')
                    if pct is None:
                        pct = data.get('total', {}).get('lines', {}).get('pct')
                    if pct is not None:
                        coverage[str(file.relative_to(root))] = pct
                except (ValueError, KeyError):
                    pass
    document = {'coverage': coverage or None, 'schema': 1, 'kind': 'quality', 'results': results, 'manual': manual, 'stack': scan, 'status': 'failed' if any(r['status'] == 'failed' for r in results) else ('incomplete' if manual or not results else 'passed')}
    (output / 'quality.json').write_text(json.dumps(document, indent=2))
    print(json.dumps(document, indent=2))
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as summary:
            summary.write(f"Quality: **{document['status']}**; {len(results)} commands. See quality-results artifact.\n\n" + '\n'.join(f'- Manual: {n}' for n in manual) + '\n')
    return 1 if document['status'] == 'failed' else 0


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', nargs='?', default='.')
    parser.add_argument('--module')
    args = parser.parse_args()
    sys.exit(main(args.root, args.module))
