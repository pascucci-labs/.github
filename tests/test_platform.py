import datetime as dt
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from common import load_script, safe_path


def module(name):
    return load_script(name)


class DiscoveryTests(unittest.TestCase):
    def test_monorepo_frameworks_and_exclusions(self):
        detect = module("detect-stack")
        contents = {
            "api/pom.xml": "<project>spring-boot</project>",
            "web/package.json": '{"dependencies":{"react":"1","typescript":"1","@angular/core":"1"}}',
            "py/pyproject.toml": "",
            "py/uv.lock": "",
            "mobile/pubspec.yaml": "sdk: flutter",
            "infra/main.tf": "",
            "Dockerfile": "",
            "compose.yaml": "",
            ".github/workflows/ci.yml": "",
            "node_modules/x/package.json": "{}",
            ".quality-platform/package.json": "{}",
        }
        scan = detect.detect(contents, contents.__getitem__)
        self.assertEqual(len(scan["modules"]), 4)
        self.assertTrue(
            {
                "spring-boot",
                "maven",
                "react",
                "angular",
                "flutter",
                "uv",
                "terraform",
                "docker",
                "compose",
                "github-actions",
            }
            <= set(scan["technologies"])
        )

    def test_local_discovery_never_reads_symlinks(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            (root / "package.json").symlink_to("/etc/passwd")
            self.assertEqual(module("detect-stack").local(root)["modules"], [])
            with self.assertRaises(ValueError):
                safe_path(root, "../outside")

    def test_workspace_install_and_child_checks(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            (root / "package-lock.json").write_text("{}")
            child = root / "apps/web"
            child.mkdir(parents=True)
            commands, _ = module("quality").auto_commands(
                root,
                {
                    "path": "apps/web",
                    "kind": "node",
                    "scripts": {"lint": "eslint .", "test": "vitest"},
                    "manifests": ["package.json"],
                },
            )
            self.assertIn((root, ["npm", "ci"]), commands)
            self.assertIn((child, ["npm", "run", "test", "--", "--run"]), commands)

    def test_unconfigured_python_is_incomplete(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            (root / "pyproject.toml").write_text('[project]\nname="example"')
            commands, notes = module("quality").auto_commands(
                root, {"path": ".", "kind": "python", "manifests": ["pyproject.toml"]}
            )
            self.assertEqual(commands, [])
            self.assertTrue(notes)


class PolicyTests(unittest.TestCase):
    def test_critical_and_secrets_cannot_be_baselined(self):
        security = module("security")
        findings = [
            security.finding("trivy", "CVE-1", "lock", severity="CRITICAL"),
            security.finding("gitleaks", "secret", "x", severity="HIGH", actionable=True),
            security.finding("semgrep", "x", "x", severity="HIGH", actionable=True),
        ]
        baseline = {
            "findings": [
                {"id": f["id"], "reason": "tracked", "expires": "2030-01-01"} for f in findings
            ]
        }
        results = security.evaluate(findings, baseline, dt.date(2026, 10, 27))
        self.assertEqual([r["blocking"] for r in results], [True, True, False])
        self.assertEqual([r["baselined"] for r in results], [False, False, True])

    def test_osv_cvss_vectors_and_commit_dependencies(self):
        security = module("security")
        vuln = {
            "id": "GHSA-example",
            "aliases": ["CVE-2026-1234"],
            "severity": [
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
            ],
            "affected": [{"ranges": [{"events": [{"fixed": "2.0"}]}]}],
        }
        data = {
            "results": [
                {
                    "source": {"path": "lock"},
                    "packages": [
                        {"package": {"name": "example", "commit": "abc"}, "vulnerabilities": [vuln]}
                    ],
                }
            ]
        }
        finding = security.normalize("osv-scanner", data)[0]
        self.assertEqual(finding["severity"], "CRITICAL")
        self.assertEqual(finding["rule"], "CVE-2026-1234")
        self.assertTrue(finding["actionable"])

    def test_expired_and_unactionable_high(self):
        security = module("security")
        finding = security.finding("trivy", "CVE-1", "lock", severity="HIGH", actionable=True)
        self.assertTrue(
            security.evaluate(
                [finding],
                {"findings": [{"id": finding["id"], "reason": "old", "expires": "2020-01-01"}]},
            )[0]["blocking"]
        )
        finding["actionable"] = False
        self.assertFalse(security.evaluate([finding], {})[0]["blocking"])
        with self.assertRaises(ValueError):
            security.evaluate([], {"findings": [{"id": "a"}]})

    def test_secret_material_not_in_normalized_output(self):
        security = module("security")
        raw = [
            {
                "RuleID": "test",
                "File": "a",
                "StartLine": 4,
                "Secret": "SUPER_SECRET_VALUE",
                "Match": "SUPER_SECRET_VALUE",
                "Fingerprint": "c:a:test:4",
            }
        ]
        self.assertNotIn("SUPER_SECRET_VALUE", json.dumps(security.normalize("gitleaks", raw)))

    def test_scanner_errors_fail_closed(self):
        security = module("security")
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "scan.json"
            output.write_text('{"results":[]}')
            with patch.object(security.subprocess, "run") as run:
                run.return_value.returncode = 2
                with self.assertRaises(RuntimeError):
                    security.run_scanner("semgrep", ["scanner"], output, {0, 1})
                run.return_value.returncode = 0
                output.write_text('{"results":[],"errors":[{}]}')
                with self.assertRaises(RuntimeError):
                    security.run_scanner("semgrep", ["scanner"], output, {0, 1})

    def test_external_performance_target_requires_authorization(self):
        perf = module("performance")
        self.assertEqual(perf.target_allowed("http://127.0.0.1:3000"), "http://127.0.0.1:3000")
        for url in [
            "https://production.example",
            "file:///etc/passwd",
            "https://user:pass@localhost",
        ]:
            with self.assertRaises(ValueError):
                perf.target_allowed(url)
        self.assertEqual(
            perf.target_allowed("https://staging.example", True), "https://staging.example"
        )


class SyncTests(unittest.TestCase):
    def setUp(self):
        self.sync = module("sync-repositories")
        self.repo = {
            "name": "example",
            "full_name": "pascucci-labs/example",
            "base": "b" * 40,
            "default_branch": "main",
            "private": True,
            "archived": False,
            "disabled": False,
        }

    def test_existing_ci_and_dependabot_preserved(self):
        paths = [".github/workflows/deploy.yml", ".github/dependabot.yml", "package.json"]
        result = self.sync.propose(self.repo, paths, "a" * 40, lambda _: "{}")
        self.assertNotIn(".github/dependabot.yml", result["files"])
        self.assertNotIn(".github/renovate.json", result["files"])
        self.assertNotIn(".github/workflows/deploy.yml", result["files"])
        self.assertEqual(
            json.loads(result["files"][".github/org-quality.json"])["quality"]["commands"], []
        )

    def test_idempotent_and_archived(self):
        result = self.sync.propose(
            self.repo, [".github/workflows/org-quality.yml"], "a" * 40, lambda _: ""
        )
        self.assertEqual(result["state"], "adopted")
        self.assertEqual(result["files"], {})
        self.assertEqual(
            self.sync.propose(self.repo | {"archived": True}, [], "a" * 40, None)["state"],
            "archived",
        )

    def test_digest_binds_exact_contents_and_refs(self):
        result = self.sync.propose(self.repo, [], "a" * 40, None)
        digest = self.sync.digest(result)
        result["files"][".github/org-quality.json"] = "tampered"
        self.assertNotEqual(digest, self.sync.digest(result))
        with self.assertRaises(ValueError):
            self.sync.apply(result, digest)
        with self.assertRaises(ValueError):
            self.sync.caller("main")

    def test_repository_listing_paginates(self):
        with patch.object(
            self.sync,
            "api",
            side_effect=[[{"name": str(i)} for i in range(100)], [{"name": "last"}]],
        ) as api:
            repos = self.sync.pages("orgs/pascucci-labs/repos")
        self.assertEqual(len(repos), 101)
        self.assertIn("page=2", api.call_args_list[-1].args[0])

    def test_stale_plan_does_not_write(self):
        plan = {
            "schema": 1,
            "organization": "pascucci-labs",
            "created": dt.datetime.now(dt.timezone.utc).isoformat(),
            "repositories": [self.sync.propose(self.repo, [], "a" * 40, None)],
        }
        calls = []

        def api(endpoint, method="GET", payload=None):
            calls.append((endpoint, method))
            if "/pulls?" in endpoint:
                return []
            if "/commits/" in endpoint:
                return {"sha": "c" * 40}
            return {"archived": False, "disabled": False}

        with (
            patch.dict(os.environ, {"GH_TOKEN": "ghs_test"}),
            patch.object(self.sync, "api", side_effect=api),
        ):
            with self.assertRaisesRegex(ValueError, "default branch changed"):
                self.sync.apply(plan, self.sync.digest(plan))
        self.assertTrue(all(method == "GET" for _, method in calls))

    def test_existing_pr_is_not_duplicated(self):
        plan = {
            "schema": 1,
            "organization": "pascucci-labs",
            "created": dt.datetime.now(dt.timezone.utc).isoformat(),
            "repositories": [self.sync.propose(self.repo, [], "a" * 40, None)],
        }
        with (
            patch.dict(os.environ, {"GH_TOKEN": "ghs_test"}),
            patch.object(
                self.sync, "api", return_value=[{"html_url": "https://example/pr/1"}]
            ) as api,
        ):
            self.sync.apply(plan, self.sync.digest(plan))
        self.assertEqual(api.call_count, 1)

    def test_incomplete_scans_do_not_close_tracking_issues(self):
        issues = module("sync-issues")
        row = {
            "repository": "pascucci-labs/example",
            "run": "https://example/run/1",
            "results": {"security": {"complete": False, "findings": []}},
        }
        self.assertEqual(issues.desired({"repositories": [row]}), [])


class WorkflowTests(unittest.TestCase):
    def test_incomplete_quality_is_not_reported_as_passed(self):
        quality = module("quality")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "pyproject.toml").write_text('[project]\nname="legacy"')
            self.assertEqual(quality.main(root), 0)
            report = json.loads((root / ".quality-results/quality.json").read_text())
            self.assertEqual(report["status"], "incomplete")
            self.assertTrue(report["manual"])

    def test_every_external_action_is_sha_pinned_and_no_unsafe_trigger(self):
        import re

        for path in (ROOT / ".github/workflows").glob("*.yml"):
            text = path.read_text()
            self.assertNotIn("pull_request_target", text)
            self.assertNotIn("secrets: inherit", text)
            for action in re.findall(r"uses:\s+([^\s]+)", text):
                self.assertRegex(action, r"@[0-9a-f]{40}$")


if __name__ == "__main__":
    unittest.main()
