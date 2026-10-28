#!/usr/bin/env python3
"""Collect trusted default-branch artifacts into a private organization report."""

import argparse
import datetime as dt
import io
import json
import subprocess
import zipfile
from pathlib import Path

from common import load_script

sync = load_script("sync-repositories")


def collect(repo):
    row = {
        "repository": repo["full_name"],
        "state": "unknown",
        "metrics": {},
        "last_successful_scan": None,
    }
    if repo["archived"] or repo["disabled"]:
        row["state"] = "archived" if repo["archived"] else "disabled"
        return row
    if repo['name'] == '.github':
        row['state'] = 'central-platform'
        return row
    try:
        workflows = sync.api(f"repos/{repo['full_name']}/actions/workflows?per_page=100")['workflows']
        caller = next((w for w in workflows if w['path'] == '.github/workflows/org-quality.yml'), None)
        if caller is None:
            row['state'] = 'missing-automation'
            return row
        if caller['state'] != 'active':
            row['state'] = 'disabled-automation'
            return row
        runs = sync.api(
            f"repos/{repo['full_name']}/actions/runs?branch={repo['default_branch']}&per_page=100"
        )["workflow_runs"]
        runs = [
            r
            for r in runs
            if r["path"] == ".github/workflows/org-quality.yml"
            and r["event"] in {"push", "schedule", "workflow_dispatch"}
        ]
        if not runs:
            row["state"] = "never-scanned"
            return row
        run = runs[0]
        row.update(
            {
                "run": run["html_url"],
                "sha": run["head_sha"],
                "updated": run["updated_at"],
                "state": run["conclusion"] or run["status"],
            }
        )
        row["last_successful_scan"] = next(
            (r["updated_at"] for r in runs if r["conclusion"] == "success"), None
        )
        age = dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(
            run["updated_at"].replace("Z", "+00:00")
        )
        if age > dt.timedelta(days=8):
            row["state"] = "stale"
        artifacts = sync.api(
            f"repos/{repo['full_name']}/actions/runs/{run['id']}/artifacts?per_page=100"
        )["artifacts"]
        documents = {}
        for artifact in artifacts:
            if artifact["expired"] or artifact["name"] not in {
                "quality-results",
                "security-results",
                "dependencies-results",
                "performance-results",
            }:
                continue
            if artifact["size_in_bytes"] > 10_000_000:
                continue
            blob = subprocess.run(
                ["gh", "api", artifact["archive_download_url"]], capture_output=True, check=True
            ).stdout
            with zipfile.ZipFile(io.BytesIO(blob)) as archive:
                for item in archive.infolist():
                    if item.file_size > 10_000_000 or item.filename.rsplit("/", 1)[-1] not in {
                        "quality.json",
                        "security.json",
                        "dependencies.json",
                        "performance.json",
                    }:
                        continue
                    data = json.loads(archive.read(item))
                    if data.get("schema") == 1:
                        documents[data["kind"]] = data
        row["results"] = documents
        row["dependency_update_prs"] = [
            {"title": p["title"], "url": p["html_url"]}
            for p in sync.pages(f"repos/{repo['full_name']}/pulls?state=open")
            if p["user"]["login"] in {"renovate[bot]", "dependabot[bot]"}
        ]
        row["persistent_quality_failure"] = False
        completed = [r for r in runs if r["status"] == "completed"][:3]
        if len(completed) == 3 and all(r["conclusion"] == "failure" for r in completed):
            jobs = [
                sync.api(f"repos/{repo['full_name']}/actions/runs/{r['id']}/jobs?per_page=100")[
                    "jobs"
                ]
                for r in completed
            ]
            row["persistent_quality_failure"] = all(
                any(
                    "quality /" in j["name"].lower() and j["conclusion"] == "failure" for j in batch
                )
                for batch in jobs
            )
        findings = {
            f["id"]: f
            for key in ("security", "dependencies")
            for f in documents.get(key, {}).get("findings", [])
        }
        row["metrics"] = {
            "critical": sum(f["severity"] == "CRITICAL" for f in findings.values())
            if all(documents.get(k, {}).get("complete") for k in ("security", "dependencies"))
            else None,
            "high": sum(f["severity"] == "HIGH" for f in findings.values())
            if all(documents.get(k, {}).get("complete") for k in ("security", "dependencies"))
            else None,
            "dependency_vulnerabilities": len(documents["dependencies"].get("findings", []))
            if "dependencies" in documents
            else None,
            "coverage": documents.get("quality", {}).get("coverage"),
            "outdated_dependencies": None,
            "performance_regressions": sum(
                bool(r.get("regression")) for r in documents["performance"].get("results", [])
            )
            if "performance" in documents
            else None,
        }
        required = {"quality", "security", "dependencies"}
        complete = required <= documents.keys() and all(
            documents[k].get("status") == "passed" for k in required
        )
        row["complete"] = complete and row["state"] == "success"
        row["last_successful_scan"] = run["updated_at"] if row["complete"] else None
        if row["state"] == "success" and not row["complete"]:
            row["state"] = "incomplete-artifacts"
        return row
    except (RuntimeError, subprocess.CalledProcessError, ValueError, KeyError, zipfile.BadZipFile):
        row["state"] = "inaccessible-or-invalid"
        return row


def markdown(report):
    lines = [
        "# Organization quality overview",
        "",
        f"Generated: {report['generated']}",
        "",
        "Unknown metrics mean unavailable evidence, never zero. Only default-branch runs are collected.",
        "",
        "| Repository | State | Critical | High | Dependencies | Coverage | Outdated | Performance | Last successful scan |",
        "|---|---|---:|---:|---:|---|---|---:|---|",
    ]
    rows = report['repositories']
    lines[4:4] = [f"Inventoried: {len(rows)}; passing with complete artifacts: {sum(bool(r.get('complete')) for r in rows)}; failing: {sum(r['state'] == 'failure' for r in rows)}; missing automation: {sum(r['state'] == 'missing-automation' for r in rows)}.", '']
    links = []
    for row in report["repositories"]:
        metrics = row.get("metrics", {})
        values = (
            [row["repository"], row["state"]]
            + [
                metrics.get(k)
                for k in (
                    "critical",
                    "high",
                    "dependency_vulnerabilities",
                    "coverage",
                    "outdated_dependencies",
                    "performance_regressions",
                )
            ]
            + [row.get("last_successful_scan")]
        )
        lines.append(
            "| "
            + " | ".join(
                str(v).replace("|", "\\|").replace("\n", " ") if v is not None else "unknown"
                for v in values
            )
            + " |"
        )
        if row.get("run"):
            links.append(f"[{row['repository']} detailed run and artifacts]({row['run']})")
    updates = ["## Pending dependency update PRs", ""]
    for row in report["repositories"]:
        for item in row.get("dependency_update_prs", []):
            title = item["title"].replace("\n", " ").replace("[", "").replace("]", "")
            updates.append(f"- {row['repository']}: [{title}]({item['url']})")
    return "\n".join(lines + [""] + links + [""] + updates) + "\n"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("organization-report"))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    report = {
        "schema": 1,
        "generated": dt.datetime.now(dt.timezone.utc).isoformat(),
        "repositories": [collect(r) for r in sync.pages("orgs/pascucci-labs/repos")],
    }
    (args.output / "report.json").write_text(json.dumps(report, indent=2))
    (args.output / "report.md").write_text(markdown(report))
    print(f"Wrote private report for {len(report['repositories'])} repositories")
