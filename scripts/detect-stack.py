#!/usr/bin/env python3
"""Manifest-based discovery; importing this module never executes repository code."""

import argparse
import json
import os
from pathlib import Path, PurePosixPath

EXCLUDE = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "vendor",
    "build",
    "dist",
    ".dart_tool",
    ".quality-platform",
    ".quality-results",
    "scratchpad",
}
MANIFESTS = {
    "pom.xml": "java",
    "build.gradle": "java",
    "build.gradle.kts": "java",
    "package.json": "node",
    "pyproject.toml": "python",
    "requirements.txt": "python",
    "setup.py": "python",
    "pubspec.yaml": "dart",
}


def detect(paths, read=None):
    paths = sorted(p for p in paths if not (set(PurePosixPath(p).parts) & EXCLUDE))
    modules = {}
    technologies = set()
    for name in paths:
        p = PurePosixPath(name)
        kind = MANIFESTS.get(p.name)
        if kind:
            entry = modules.setdefault(
                (str(p.parent), kind), {"path": str(p.parent), "kind": kind, "manifests": []}
            )
            entry["manifests"].append(p.name)
            technologies.add(kind)
            if p.name == "pom.xml":
                technologies.add("maven")
            if p.name.startswith("build.gradle"):
                technologies.add("gradle")
            if read:
                content = read(name)
                if kind == "node":
                    try:
                        package = json.loads(content)
                        deps = package.get("dependencies", {}) | package.get("devDependencies", {})
                        entry["scripts"] = package.get("scripts", {})
                        technologies.update(
                            t for t in ("react", "svelte", "typescript") if t in deps
                        )
                        if "@angular/core" in deps:
                            technologies.add("angular")
                    except (ValueError, TypeError):
                        entry["error"] = "invalid package.json"
                if kind == "dart" and "sdk: flutter" in content:
                    entry["kind"] = "flutter"
                    technologies.add("flutter")
                if kind == "java" and (
                    "spring-boot" in content or "org.springframework.boot" in content
                ):
                    technologies.add("spring-boot")
        if p.name == "uv.lock":
            technologies.add("uv")
        if p.name in {"Dockerfile", "Containerfile"} or p.name.startswith("Dockerfile."):
            technologies.add("docker")
        if p.name in {"compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml"}:
            technologies.add("compose")
        if p.suffix == ".tf":
            technologies.add("terraform")
        if name.startswith(".github/workflows/") and p.suffix in {".yml", ".yaml"}:
            technologies.add("github-actions")
        if p.suffix in {".html", ".css"}:
            technologies.add(p.suffix[1:])
    workflows = [
        p
        for p in paths
        if p.startswith(".github/workflows/") and PurePosixPath(p).suffix in {".yml", ".yaml"}
    ]
    return {
        "technologies": sorted(technologies),
        "modules": list(modules.values()),
        "workflows": workflows,
        "dependency_configs": [
            p
            for p in paths
            if PurePosixPath(p).name
            in {
                "dependabot.yml",
                "dependabot.yaml",
                "renovate.json",
                "renovate.json5",
                ".renovaterc",
                ".renovaterc.json",
            }
        ],
    }


def local(root):
    root = Path(root).resolve()
    paths = []
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(
            d for d in dirs if d not in EXCLUDE and not (Path(current) / d).is_symlink()
        )
        paths.extend(
            str((Path(current) / f).relative_to(root))
            for f in files
            if not (Path(current) / f).is_symlink()
        )
    return detect(paths, lambda p: (root / p).read_text(errors="replace"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".")
    args = parser.parse_args()
    print(json.dumps(local(args.root), indent=2))
