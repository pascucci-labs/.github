"""Shared path, configuration, and command helpers."""

import importlib.util
import json
import subprocess
from pathlib import Path

PLATFORM = Path(__file__).resolve().parent.parent


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, PLATFORM / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def safe_path(root, relative):
    root = Path(root).resolve()
    path = (root / relative).resolve()
    if not path.is_relative_to(root):
        raise ValueError(f"Path escapes repository: {relative}")
    return path


def configuration(root):
    path = safe_path(root, ".github/org-quality.json")
    return json.loads(path.read_text()) if path.exists() else {}


def execute(argv, cwd, **kwargs):
    print("+ " + " ".join(map(str, argv)), flush=True)
    subprocess.run(argv, cwd=cwd, check=True, **kwargs)
