#!/usr/bin/env python3
"""Free scanners, normalized reports, and explicit blocking policy."""

import argparse
import datetime as dt
import hashlib
import json
import math
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath

from common import PLATFORM, configuration, safe_path, load_script


def finding(
    tool,
    rule,
    path,
    line=1,
    severity="UNKNOWN",
    actionable=False,
    package="",
    fixed="",
    identity=None,
):
    # Package vulnerability IDs deliberately do not include the scanner, so
    # OSV and Trivy findings can deduplicate when they use the same CVE alias.
    raw = identity or f"{tool}|{rule}|{path}|{line}|{package}"
    return {
        "id": hashlib.sha256(raw.encode()).hexdigest()[:24],
        "tool": tool,
        "rule": rule,
        "path": path,
        "line": line,
        "severity": severity.upper(),
        "actionable": actionable,
        "package": package,
        "fixed": fixed,
    }


def osv_severity(vuln):
    declared = vuln.get("database_specific", {}).get("severity", "").upper()
    if declared in {"CRITICAL", "HIGH", "MEDIUM", "MODERATE", "LOW"}:
        return declared
    scores = []
    for severity in vuln.get("severity", []):
        vector = severity.get("score", "")
        if not vector.startswith(("CVSS:3.0/", "CVSS:3.1/")):
            continue
        try:
            m = dict(part.split(":", 1) for part in vector.split("/")[1:])
            changed = m["S"] == "C"
            impact_base = 1 - math.prod(
                1 - {"H": 0.56, "L": 0.22, "N": 0}[m[k]] for k in ("C", "I", "A")
            )
            impact = (
                7.52 * (impact_base - 0.029) - 3.25 * (impact_base - 0.02) ** 15
                if changed
                else 6.42 * impact_base
            )
            privilege = {
                "N": 0.85,
                "L": 0.68 if changed else 0.62,
                "H": 0.50 if changed else 0.27,
            }[m["PR"]]
            exploit = (
                8.22
                * {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
                * {"L": 0.77, "H": 0.44}[m["AC"]]
                * privilege
                * {"N": 0.85, "R": 0.62}[m["UI"]]
            )
            score = (
                math.ceil(min((impact + exploit) * (1.08 if changed else 1), 10) * 10 - 1e-8) / 10
                if impact > 0
                else 0
            )
            scores.append(score)
        except (KeyError, ValueError):
            continue
    score = max(scores, default=None)
    if score is None:
        return "UNKNOWN"
    return "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"


def normalize(tool, data):
    found = []
    if tool == "gitleaks":
        for item in data:
            record = finding(
                tool,
                item["RuleID"],
                item["File"],
                item.get("StartLine", 1),
                "HIGH",
                True,
                identity="gitleaks|"
                + item.get(
                    "Fingerprint",
                    f"{item['RuleID']}:{item['File']}:{item.get('StartLine', 1)}",
                ),
            )
            # History findings must point to their original commit, even if the
            # current file was moved/deleted. Neither field contains a secret.
            record["commit"] = item.get("Commit", "")
            record["fingerprint"] = item.get("Fingerprint", "")
            found.append(record)
    elif tool == "semgrep":
        for item in data.get("results", []):
            meta = item["extra"].get("metadata", {})
            found.append(
                finding(
                    tool,
                    item["check_id"],
                    item["path"],
                    item["start"]["line"],
                    meta.get("severity", "MEDIUM"),
                    meta.get("confirmed") is True,
                )
            )
    elif tool == "trivy":
        for result in data.get("Results", []):
            path = result.get("Target", "")
            for item in result.get("Vulnerabilities", []):
                rule = item["VulnerabilityID"]
                package = item["PkgName"] + "@" + item["InstalledVersion"]
                found.append(
                    finding(
                        tool,
                        rule,
                        path,
                        severity=item["Severity"],
                        actionable=bool(item.get("FixedVersion")),
                        package=package,
                        fixed=item.get("FixedVersion", ""),
                        identity=f"dep|{path}|{package}|{rule}",
                    )
                )
            for item in result.get("Misconfigurations", []):
                cause = item.get("CauseMetadata", {})
                found.append(
                    finding(
                        tool,
                        item["ID"],
                        path,
                        cause.get("StartLine", 1),
                        item["Severity"],
                        True,
                    )
                )
    elif tool == "osv-scanner":
        for result in data.get("results", []):
            path = result["source"]["path"]
            for item in result.get("packages", []):
                package = (
                    item["package"]["name"]
                    + "@"
                    + item["package"].get("version", item["package"].get("commit", "unknown"))
                )
                for vuln in item.get("vulnerabilities", []):
                    aliases = [
                        a for a in [vuln["id"]] + vuln.get("aliases", []) if a.startswith("CVE-")
                    ]
                    rule = sorted(aliases)[0] if aliases else vuln["id"]
                    severity = osv_severity(vuln)
                    fixes = sorted(
                        {
                            event["fixed"]
                            for r in vuln.get("affected", [])
                            for rng in r.get("ranges", [])
                            for event in rng.get("events", [])
                            if "fixed" in event
                        }
                    )
                    found.append(
                        finding(
                            tool,
                            rule,
                            path,
                            severity=severity,
                            actionable=bool(fixes),
                            package=package,
                            fixed=", ".join(fixes),
                            identity=f"dep|{path}|{package}|{rule}",
                        )
                    )
    return found


def evaluate(findings, baseline, today=None):
    today = today or dt.date.today()
    accepted = {}
    for item in baseline.get("findings", []):
        if not item.get("reason") or not item.get("expires"):
            raise ValueError("Baseline entries require reason and expires")
        if item["id"] in accepted:
            raise ValueError("Duplicate baseline ID")
        accepted[item["id"]] = dt.date.fromisoformat(item["expires"]) >= today
    result = []
    for item in findings:
        item = dict(item)
        protected = item["severity"] == "CRITICAL" or item["tool"] == "gitleaks"
        item["baselined"] = not protected and accepted.get(item["id"], False)
        item["blocking"] = protected or (
            item["severity"] == "HIGH" and item["actionable"] and not item["baselined"]
        )
        result.append(item)
    return result


def run_scanner(tool, argv, output, allowed):
    # Capture all scanner output: no source excerpts or secret values enter logs.
    result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode not in allowed or not output.is_file():
        raise RuntimeError(
            f"{tool} did not complete (exit {result.returncode}); scanner output withheld"
        )
    data = json.loads(output.read_text())
    if tool == "semgrep" and data.get("errors"):
        raise RuntimeError("Semgrep reported incomplete analysis")
    return normalize(tool, data)


def validate_gitleaks_ignore(text):
    """Accept exact, explained historical fingerprints, never path/rule wildcards."""
    fingerprints = []
    reason = ""
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("#"):
            reason = line[1:].strip()
            continue
        match = re.fullmatch(r"([0-9a-f]{40}):([^\r\n]+):([A-Za-z0-9_-]+):([1-9][0-9]*)", line)
        if not match or any(character in line for character in "*?[]") or len(reason) < 12:
            raise ValueError(
                "Gitleaks exceptions require exact fingerprints and explanatory comments"
            )
        path = PurePosixPath(match.group(2))
        if path.is_absolute() or ".." in path.parts or any(ord(c) < 32 for c in line):
            raise ValueError("Invalid historical finding path")
        if line in fingerprints:
            raise ValueError("Duplicate historical fingerprint")
        fingerprints.append(line)
        reason = ""
    return fingerprints


def trusted_gitleaks_ignore(root, destination, environ=None):
    """Only the PR base can authorize exceptions; PR-head config never weakens its scan."""
    environ = os.environ if environ is None else environ
    if environ.get("GITHUB_EVENT_NAME") == "pull_request":
        event = json.loads(Path(environ["GITHUB_EVENT_PATH"]).read_text())
        revision = event["pull_request"]["base"]["sha"]
    elif environ.get("GITHUB_EVENT_NAME"):
        event = json.loads(Path(environ["GITHUB_EVENT_PATH"]).read_text())
        default_branch = event["repository"]["default_branch"]
        if environ.get("GITHUB_REF") == f"refs/heads/{default_branch}":
            revision = environ["GITHUB_SHA"]
        else:
            # A manual feature-branch run must not turn its unreviewed ignore
            # file into a passing security status for that PR.
            revision = subprocess.run(
                [
                    "git",
                    "rev-parse",
                    "--verify",
                    f"refs/remotes/origin/{default_branch}^{{commit}}",
                ],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
    else:
        revision = environ.get("GITHUB_SHA")
        if not revision:
            revision = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("Invalid trusted revision")
    # ls-tree distinguishes a genuinely absent ignore file from a missing Git
    # object/permission failure. Symlinks and submodules cannot provide policy.
    entry = subprocess.run(
        ["git", "ls-tree", revision, "--", ".gitleaksignore"],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    text = ""
    if entry:
        if not entry.startswith(("100644 blob ", "100755 blob ")):
            raise ValueError("Historical exceptions must be a regular tracked file")
        text = subprocess.run(
            ["git", "show", f"{revision}:.gitleaksignore"],
            cwd=root,
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    entries = validate_gitleaks_ignore(text)
    # Exceptions can only describe already-merged history, never pre-authorize
    # a credential on another branch for a future PR.
    for commit in sorted({entry.split(":", 1)[0] for entry in entries}):
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", commit, revision],
            cwd=root,
            check=True,
            capture_output=True,
        )
    destination.write_text("\n".join(entries) + ("\n" if entries else ""))
    return {"revision": revision, "fingerprints": entries}


def main(root, mode):
    root = Path(root).resolve()
    output = root / ".quality-results"
    output.mkdir(exist_ok=True)
    findings = []
    errors = []
    history_exceptions = None
    config = configuration(root).get("security", {})
    with tempfile.TemporaryDirectory(prefix="quality-scan-") as temp:
        raw = Path(temp)
        scanners = []
        (raw / "ignore").write_text("")
        (raw / "osv.toml").write_text("")
        if mode == "security":
            scanners.append(
                (
                    "semgrep",
                    [
                        "semgrep",
                        "scan",
                        "--metrics=off",
                        "--disable-version-check",
                        "--quiet",
                        "--disable-nosem",
                        "--config",
                        str(PLATFORM / "config/semgrep"),
                        "--exclude",
                        ".quality-platform",
                        "--exclude",
                        ".quality-results",
                        "--json-output",
                        str(raw / "semgrep.json"),
                        str(root),
                    ],
                    {0, 1},
                )
            )
            try:
                history_exceptions = trusted_gitleaks_ignore(root, raw / "gitleaks-ignore")
            except (ValueError, OSError, KeyError, subprocess.CalledProcessError):
                errors.append(
                    "gitleaks: trusted exception policy could not be loaded; analysis incomplete"
                )
            gitleaks = [
                "gitleaks",
                "git",
                str(root / ".git"),
                "--gitleaks-ignore-path",
                str(raw / "gitleaks-ignore"),
                "--ignore-gitleaks-allow",
                "--exit-code=10",
                "--redact=100",
                "--no-banner",
                "--config",
                str(PLATFORM / "config/gitleaks/gitleaks.toml"),
                "--report-format",
                "json",
                "--report-path",
                str(raw / "gitleaks.json"),
            ]
            if os.environ.get("GITHUB_EVENT_NAME") == "pull_request":
                event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
                base, head = (
                    event["pull_request"]["base"]["sha"],
                    event["pull_request"]["head"]["sha"],
                )
                if not all(re.fullmatch("[0-9a-f]{40}", s) for s in (base, head)):
                    raise ValueError("Invalid commit SHA")
                gitleaks += ["--log-opts", f"{base}..{head}"]
            if history_exceptions is not None:
                scanners.append(("gitleaks", gitleaks, {0, 10}))
            scanners.append(
                (
                    "trivy",
                    [
                        "trivy",
                        "config",
                        "--config",
                        str(PLATFORM / "config/trivy/trivy.yaml"),
                        "--ignorefile",
                        str(raw / "ignore"),
                        "--format",
                        "json",
                        "--output",
                        str(raw / "trivy.json"),
                        str(root),
                    ],
                    {0},
                )
            )
        else:
            scanners.append(
                (
                    "trivy",
                    [
                        "trivy",
                        "fs",
                        "--config",
                        str(PLATFORM / "config/trivy/trivy.yaml"),
                        "--scanners",
                        "vuln",
                        "--ignorefile",
                        str(raw / "ignore"),
                        "--format",
                        "json",
                        "--output",
                        str(raw / "trivy.json"),
                        str(root),
                    ],
                    {0},
                )
            )
            scanners.append(
                (
                    "osv-scanner",
                    [
                        "osv-scanner",
                        "scan",
                        "source",
                        "--recursive",
                        "--config",
                        str(raw / "osv.toml"),
                        "--format",
                        "json",
                        "--output",
                        str(raw / "osv-scanner.json"),
                        str(root),
                    ],
                    {0, 1},
                )
            )
        supported = {
            "package-lock.json",
            "pnpm-lock.yaml",
            "yarn.lock",
            "uv.lock",
            "poetry.lock",
            "requirements.txt",
            "pubspec.lock",
            "pom.xml",
            "gradle.lockfile",
            "go.mod",
            "Cargo.lock",
            "Gemfile.lock",
            "composer.lock",
            "Pipfile.lock",
            "pylock.toml",
            "pdm.lock",
            "bun.lock",
        }
        manifests = []
        for current, dirs, files in os.walk(root):
            dirs[:] = [
                d
                for d in dirs
                if d not in load_script("detect-stack").EXCLUDE
                and not (Path(current) / d).is_symlink()
            ]
            manifests.extend(f for f in files if f in supported)
        scanners = [s for s in scanners if s[0] != "osv-scanner" or manifests]
        for tool, argv, allowed in scanners:
            try:
                findings.extend(run_scanner(tool, argv, raw / f"{tool}.json", allowed))
            except (RuntimeError, OSError, ValueError, KeyError) as error:
                errors.append(f"{tool}: {type(error).__name__}; analysis incomplete")
        # Only explicitly configured immutable images; never build or run an image.
        for index, image in enumerate(config.get("images", [])):
            if not re.fullmatch(r"[A-Za-z0-9._:/-]+@sha256:[0-9a-f]{64}", image):
                errors.append("Container image must be pinned by sha256 digest")
                continue
            try:
                findings.extend(
                    run_scanner(
                        "trivy",
                        [
                            "trivy",
                            "image",
                            "--scanners",
                            "vuln",
                            "--ignorefile",
                            str(raw / "ignore"),
                            "--format",
                            "json",
                            "--output",
                            str(raw / f"image-{index}.json"),
                            image,
                        ],
                        raw / f"image-{index}.json",
                        {0},
                    )
                )
            except (RuntimeError, OSError, ValueError, KeyError):
                errors.append("Container image analysis incomplete")
    # Normalize absolute manifest paths before dependency deduplication.
    unique = {}
    for item in findings:
        p = Path(item["path"])
        if p.is_absolute() and p.is_relative_to(root):
            item["path"] = str(p.relative_to(root))
        if item["package"]:
            item["id"] = hashlib.sha256(
                f"dep|{item['path']}|{item['package']}|{item['rule']}".encode()
            ).hexdigest()[:24]
        previous = unique.get(item["id"])
        rank = {
            "UNKNOWN": 0,
            "LOW": 1,
            "MODERATE": 2,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }
        if not previous or rank.get(item["severity"], 0) > rank.get(previous["severity"], 0):
            unique[item["id"]] = item
    # Path-based findings must have stable IDs across checkout locations.
    for item in unique.values():
        if not item["package"] and item["tool"] != "gitleaks":
            item["id"] = hashlib.sha256(
                f"{item['tool']}|{item['rule']}|{item['path']}|{item['line']}|".encode()
            ).hexdigest()[:24]
    baseline_path = safe_path(root, ".github/quality-baseline.json")
    baseline = json.loads(baseline_path.read_text()) if baseline_path.exists() else {}
    findings = evaluate(list(unique.values()), baseline)
    if mode == "dependencies" and not manifests and not config.get("images"):
        applicability = "no-supported-dependency-files"
    else:
        applicability = "applicable"
    document = {
        "gitleaks_exceptions": history_exceptions,
        "applicability": applicability,
        "schema": 1,
        "kind": mode,
        "status": "failed" if errors or any(f["blocking"] for f in findings) else "passed",
        "complete": not errors,
        "errors": errors,
        "findings": findings,
    }
    (output / f"{mode}.json").write_text(json.dumps(document, indent=2))
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as summary:
            summary.write(
                f"{mode}: **{document['status']}**, {len(findings)} findings, {len(errors)} scanner errors.\n\nSee sanitized JSON in {mode}-results artifact; critical findings and secrets always block.\n"
            )
    for item in findings:
        if item["blocking"]:
            # Fixed metadata only; no scanner messages, source snippets, secrets.
            path = (
                item["path"]
                .replace("%", "%25")
                .replace("\r", "%0D")
                .replace("\n", "%0A")
                .replace(",", "%2C")
                .replace(":", "%3A")
            )
            line = int(item["line"] or 1)
            print(
                f"::error file={path},line={line}::Blocking security finding {item['id']}; see sanitized artifact"
            )
    for error in errors:
        print("::error::" + error)
    return int(document["status"] != "passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".")
    parser.add_argument("--mode", choices=["security", "dependencies"], default="security")
    args = parser.parse_args()
    sys.exit(main(args.root, args.mode))
