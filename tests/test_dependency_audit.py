"""Synthetic audit fixtures; no feed access or target package installs."""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "dependency_audit", Path(__file__).resolve().parents[1] / "scripts" / "dependency_audit.py"
)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class DependencyAuditTests(unittest.TestCase):
    def setUp(self):
        self.locked = [("diskcache", "5.6.3"), ("pypdf", "6.21.2")]

    def python_output(self, vulns):
        return json.dumps({"dependencies": [
            {"name": "diskcache", "version": "5.6.3", "vulns": vulns},
            {"name": "pypdf", "version": "6.21.2", "vulns": []},
        ]})

    def npm_output(self, total, via=None):
        return json.dumps({"metadata": {"vulnerabilities": {"total": total}},
                           "vulnerabilities": {} if via is None else {
                               "undici": {"via": via}}})

    def test_clean(self):
        self.assertEqual(audit.python_result(self.python_output([]), 0, self.locked),
                         ("clean", []))
        self.assertEqual(audit.npm_result(self.npm_output(0), 0),
                         ("clean", ["npm reports 0 vulnerable package(s)"]))

    def test_vulnerable(self):
        py = audit.python_result(self.python_output([{"id": "GHSA-example"}]), 1, self.locked)
        npm = audit.npm_result(self.npm_output(1, [{"title": "example", "url": "https://example.test/advisory"}]), 1)
        self.assertEqual(py, ("findings", ["diskcache 5.6.3: GHSA-example"]))
        self.assertEqual(npm[0], "findings")
        self.assertIn("undici: https://example.test/advisory", npm[1])

    def test_duplicate_advisory(self):
        duplicate = [{"id": "GHSA-example"}, {"id": "GHSA-example"}]
        self.assertEqual(audit.python_result(self.python_output(duplicate), 1, self.locked)[1],
                         ["diskcache 5.6.3: GHSA-example"])
        via = [{"title": "example", "source": 17}, {"title": "example", "source": 17}]
        self.assertEqual(audit.npm_result(self.npm_output(1, via), 1)[1].count("undici: 17"), 1)

    def test_feed_or_tool_unavailable(self):
        self.assertEqual(audit.python_result("service unavailable", 2, self.locked)[0], "error")
        self.assertEqual(audit.npm_result(json.dumps({"error": {"code": "EAUDIT"}}), 1)[0], "error")
        self.assertEqual(audit.npm_result("", 1)[0], "error")

    def test_incomplete_or_conflicting_results_fail_closed(self):
        self.assertEqual(audit.python_result(self.python_output([]), 1, self.locked)[0], "error")
        self.assertEqual(audit.python_result(self.python_output([]), 0, self.locked[:1])[0], "error")
        self.assertEqual(audit.npm_result(self.npm_output(0), 1)[0], "error")

    def test_python_command_exports_whole_lock_without_installing_project(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "pyproject.toml").write_text('[project]\nname = "local-project"\n')
            (root / "uv.lock").write_text('''[[package]]
name = "local-project"
version = "0.1.0"
[[package]]
name = "diskcache"
version = "5.6.3"
[[package]]
name = "pypdf"
version = "6.21.2"
''')

            def fake_run(command, **kwargs):
                self.assertEqual(command[:2], ["pip-audit", "-r"])
                self.assertEqual(command[3:], ["--no-deps", "--disable-pip", "-f", "json"])
                self.assertEqual(Path(command[2]).read_text(),
                                 "diskcache==5.6.3\npypdf==6.21.2\n")
                return SimpleNamespace(stdout=self.python_output([]), stderr="", returncode=0)

            with patch.object(audit.subprocess, "run", side_effect=fake_run):
                self.assertEqual(audit.run_python(root)[0][0], "clean")

    def test_npm_command_reads_lock_without_installing_packages(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "web").mkdir()
            (root / "web" / "package-lock.json").write_text("{}")
            with patch.object(audit.subprocess, "run", return_value=SimpleNamespace(
                    stdout=self.npm_output(0), stderr="", returncode=0)) as run:
                self.assertEqual(audit.run_npm(root)[0][0], "clean")
                self.assertEqual(run.call_args.args[0], ["npm", "audit", "--json", "--audit-level=low"])
                self.assertEqual(run.call_args.kwargs["cwd"], root / "web")


if __name__ == "__main__":
    unittest.main()
