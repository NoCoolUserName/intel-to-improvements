#!/usr/bin/env python3
"""Audit the complete Python and frontend locks without installing the project."""

import json
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def locked_python_packages(root=ROOT):
    project = tomllib.loads((root / "pyproject.toml").read_text())["project"]["name"]
    packages = tomllib.loads((root / "uv.lock").read_text())["package"]
    locked = sorted({(p["name"], p["version"]) for p in packages if p["name"] != project})
    if not locked:
        raise ValueError("Python lock contains no external packages")
    return locked


def python_result(output, code, locked):
    try:
        data = json.loads(output)
        dependencies = data["dependencies"]
        actual = {(p["name"], p["version"]) for p in dependencies}
        if actual != set(locked):
            raise ValueError("audit response does not cover the complete Python lock")
        findings = sorted({(p["name"], p["version"], v["id"])
                           for p in dependencies for v in p["vulns"]})
    except (ValueError, KeyError, TypeError) as exc:
        return "error", [f"Python audit response unavailable or incomplete: {exc}"]
    if code not in (0, 1) or code != (1 if findings else 0):
        return "error", [f"pip-audit exit {code} conflicts with its advisory results"]
    return ("findings" if findings else "clean"), [
        f"{name} {version}: {advisory}" for name, version, advisory in findings
    ]


def npm_result(output, code):
    try:
        data = json.loads(output)
        if "error" in data:
            raise ValueError(str(data["error"]))
        total = data["metadata"]["vulnerabilities"]["total"]
        vulnerabilities = data["vulnerabilities"]
        if not isinstance(total, int) or total < 0 or not isinstance(vulnerabilities, dict):
            raise ValueError("invalid npm advisory summary")
        ids = set()
        for package, item in vulnerabilities.items():
            for via in item["via"]:
                if isinstance(via, dict):
                    ids.add((package, str(via.get("url") or via.get("source") or via["title"])))
    except (ValueError, KeyError, TypeError) as exc:
        return "error", [f"npm audit response unavailable or incomplete: {exc}"]
    if code not in (0, 1) or code != (1 if total else 0):
        return "error", [f"npm audit exit {code} conflicts with its advisory results"]
    return ("findings" if total else "clean"), [
        f"npm reports {total} vulnerable package(s)"
    ] + [f"{package}: {advisory}" for package, advisory in sorted(ids)]


def run_python(root=ROOT):
    locked = locked_python_packages(root)
    with tempfile.TemporaryDirectory() as directory:
        requirements = Path(directory) / "locked-requirements.txt"
        requirements.write_text("".join(f"{name}=={version}\n" for name, version in locked))
        completed = subprocess.run(
            ["pip-audit", "-r", str(requirements), "--no-deps", "--disable-pip", "-f", "json"],
            cwd=root, capture_output=True, text=True, check=False,
        )
    return python_result(completed.stdout, completed.returncode, locked), completed.stderr


def run_npm(root=ROOT):
    if not (root / "web" / "package-lock.json").is_file():
        raise ValueError("frontend lockfile missing")
    completed = subprocess.run(
        ["npm", "audit", "--json", "--audit-level=low"],
        cwd=root / "web", capture_output=True, text=True, check=False,
    )
    return npm_result(completed.stdout, completed.returncode), completed.stderr


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ("python", "npm"):
        print("usage: dependency_audit.py python|npm", file=sys.stderr)
        return 2
    try:
        (status, details), stderr = (run_python() if sys.argv[1] == "python" else run_npm())
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        status, details, stderr = "error", [str(exc)], ""
    print(f"{sys.argv[1]} dependency audit: {status}")
    for detail in details:
        print(detail)
    if status == "error" and stderr:
        print(stderr.strip(), file=sys.stderr)
    return {"clean": 0, "findings": 1, "error": 2}[status]


if __name__ == "__main__":
    sys.exit(main())
