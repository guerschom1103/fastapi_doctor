import json
import io
import subprocess
import sys
from pathlib import Path

from modules.utils.progress import ProgressUI

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "fastapi_doctor.py"

def audit(tmp_path, *args):
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--path", str(tmp_path), "--no-external", *args],
        capture_output=True, text=True
    )

def test_clean_project(tmp_path):
    (tmp_path / "main.py").write_text(
        "from fastapi import FastAPI\napp = FastAPI()\n\ndef add(a: int, b: int) -> int:\n    return a+b\n",
        encoding="utf-8"
    )
    r = audit(tmp_path, "--format", "json")
    assert r.returncode == 0
    d = json.loads(r.stdout)
    assert d["score"] == 100
    assert d["detected"]["fastapi"] is True

def test_syntax_error(tmp_path):
    (tmp_path / "bad.py").write_text("def broken(\n", encoding="utf-8")
    r = audit(tmp_path, "--format", "json")
    assert r.returncode == 1
    d = json.loads(r.stdout)
    assert any(x["rule_id"] == "PY-SYNTAX" for x in d["findings"])

def test_security_eval(tmp_path):
    (tmp_path / "bad.py").write_text(
        "def execute(x: str):\n    return eval(x)\n", encoding="utf-8"
    )
    r = audit(tmp_path, "--format", "json")
    assert r.returncode == 1
    d = json.loads(r.stdout)
    assert any(x["rule_id"] == "SEC-EVAL" for x in d["findings"])

def test_html_report(tmp_path):
    (tmp_path / "main.py").write_text("print('ok')\n", encoding="utf-8")
    out = tmp_path / "report.html"
    r = audit(tmp_path, "--format", "html", "--output", str(out))
    assert r.returncode == 0
    assert out.exists()
    assert "FastAPI Doctor v3" in out.read_text(encoding="utf-8")

def test_sarif_report(tmp_path):
    (tmp_path / "main.py").write_text("print('ok')\n", encoding="utf-8")
    out = tmp_path / "report.sarif"
    r = audit(tmp_path, "--format", "sarif", "--output", str(out))
    assert r.returncode == 0
    d = json.loads(out.read_text(encoding="utf-8"))
    assert d["version"] == "2.1.0"

def test_env_file_is_visible_and_scanned(tmp_path):
    (tmp_path / "main.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8")
    (tmp_path / ".env").write_text(
        "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK...\n-----END RSA PRIVATE KEY-----\n",
        encoding="utf-8"
    )
    r = audit(tmp_path, "--format", "json", "--deep")
    assert r.returncode == 1
    d = json.loads(r.stdout)
    assert d["metrics"]["env_files"] == 1
    assert any(f["rule_id"] == "SEC-SECRET-SCAN" for f in d["findings"])
    assert any(f["rule_id"] == "SEC-ENV-FILE" for f in d["findings"])

def test_env_variant_is_scanned(tmp_path):
    (tmp_path / "main.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8")
    (tmp_path / ".env.production").write_text(
        "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK...\n-----END RSA PRIVATE KEY-----\n",
        encoding="utf-8"
    )
    r = audit(tmp_path, "--format", "json", "--deep")
    d = json.loads(r.stdout)
    assert any(f["rule_id"] == "SEC-SECRET-SCAN" for f in d["findings"])

def test_skip_dirs_still_pruned(tmp_path):
    (tmp_path / "main.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8")
    nm = tmp_path / "node_modules" / "pkg"
    nm.mkdir(parents=True)
    (nm / "AWS_ACCESS_KEY_ID.js").write_text(
        "aws_access_key_id = 'AKIAABCDEFGHIJKLMNOP'\n", encoding="utf-8"
    )
    r = audit(tmp_path, "--format", "json", "--deep")
    d = json.loads(r.stdout)
    assert d["metrics"]["python_files"] == 1
    assert not any("node_modules" in (f.get("file") or "") for f in d["findings"])

def test_data_flow_analysis(tmp_path):
    """Test data flow analysis feature."""
    (tmp_path / "leak.py").write_text("""
password = "secret123"
print(f"Password is: {password}")
logger.info(f"User password: {password}")
""", encoding="utf-8")
    r = audit(tmp_path, "--deep", "--format", "json")
    d = json.loads(r.stdout)
    # Check for data flow findings
    data_flow_findings = [f for f in d["findings"] if "DATAFLOW" in f.get("rule_id", "")]
    assert len(data_flow_findings) > 0

def test_sql_injection_analysis(tmp_path):
    """Test SQL injection analysis feature."""
    (tmp_path / "injection.py").write_text("""
def unsafe_query(user_input):
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    return query
""", encoding="utf-8")
    r = audit(tmp_path, "--deep", "--format", "json")
    d = json.loads(r.stdout)
    # Check for SQL injection findings
    sql_findings = [f for f in d["findings"] if "SQL-INJECTION" in f.get("rule_id", "")]
    assert len(sql_findings) > 0

def test_async_analysis(tmp_path):
    """Test async analysis feature."""
    (tmp_path / "async_bad.py").write_text("""
async def process():
    time.sleep(5)  # Blocking in async
    return "done"
""", encoding="utf-8")
    r = audit(tmp_path, "--deep", "--format", "json")
    d = json.loads(r.stdout)
    # Check for async findings
    async_findings = [f for f in d["findings"] if "ASYNC" in f.get("rule_id", "")]
    assert len(async_findings) > 0

def test_progress_is_sent_to_stderr_without_corrupting_json(tmp_path):
    (tmp_path / "main.py").write_text("print('ok')\n", encoding="utf-8")
    r = audit(tmp_path, "--format", "json", "--progress", "always")
    data = json.loads(r.stdout)
    assert data["project"] == tmp_path.name
    assert "Exploration du projet" in r.stderr
    assert "Audit termine" in r.stderr

def test_targeted_performance_analysis(tmp_path):
    (tmp_path / "main.py").write_text(
        "def find(items):\n    for item in items:\n        if item in items:\n            return item\n",
        encoding="utf-8",
    )
    r = audit(tmp_path, "--format", "json", "--analyze-performance")
    data = json.loads(r.stdout)
    assert data["performance_metrics"] is not None
    assert data["dependency_graph"] is None

def test_dict_get_in_loop_is_not_reported_as_n_plus_one(tmp_path):
    (tmp_path / "cache.py").write_text(
        "def values(items, cache):\n    return [cache.get(item) for item in items]\n",
        encoding="utf-8",
    )
    r = audit(tmp_path, "--deep", "--format", "json")
    data = json.loads(r.stdout)
    assert not any(f["rule_id"] == "PERF-N-PLUS-ONE" for f in data["findings"])

def test_normal_append_in_loop_is_not_reported(tmp_path):
    (tmp_path / "items.py").write_text(
        "def double(items):\n    result = []\n    for item in items:\n        result.append(item * 2)\n    return result\n",
        encoding="utf-8",
    )
    r = audit(tmp_path, "--deep", "--format", "json")
    data = json.loads(r.stdout)
    assert not any(f["rule_id"] == "PERF-LIST-IN-LOOP" for f in data["findings"])

def test_tests_are_excluded_from_heuristics_by_default(tmp_path):
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_queries.py").write_text(
        "def test_query(db, items):\n    for item in items:\n        db.query(item)\n",
        encoding="utf-8",
    )
    (tmp_path / "main.py").write_text("print('ok')\n", encoding="utf-8")
    r = audit(tmp_path, "--deep", "--format", "json")
    data = json.loads(r.stdout)
    assert not any(f["rule_id"] == "PERF-N-PLUS-ONE" for f in data["findings"])

def test_self_and_cls_are_not_reported_as_untyped(tmp_path):
    (tmp_path / "model.py").write_text(
        "class Model:\n    def save(self) -> None:\n        pass\n\n    @classmethod\n    def load(cls) -> None:\n        pass\n",
        encoding="utf-8",
    )
    r = audit(tmp_path, "--deep", "--format", "json")
    data = json.loads(r.stdout)
    assert not any(f["rule_id"] == "PY-UNTYPED" for f in data["findings"])

def test_html_report_is_french_and_filterable(tmp_path):
    (tmp_path / "main.py").write_text("print('ok')\n", encoding="utf-8")
    out = tmp_path / "report.html"
    audit(tmp_path, "--format", "html", "--output", str(out))
    report = out.read_text(encoding="utf-8")
    assert "Tous les signalements" in report
    assert "Toutes les confiances" in report
    assert "Priorités à examiner" in report

def test_english_update_text_is_not_sql(tmp_path):
    (tmp_path / "messages.py").write_text(
        'def message(name):\n    return f"Please update user {name} before deployment"\n',
        encoding="utf-8",
    )
    r = audit(tmp_path, "--deep", "--format", "json")
    data = json.loads(r.stdout)
    assert not any("SQL-INJECTION" in (f["rule_id"] or "") for f in data["findings"])

def test_doctor_mascot_color_reflects_health():
    healthy_stream = io.StringIO()
    ProgressUI("always", healthy_stream).summary(96, [])
    assert "\033[32m" in healthy_stream.getvalue()
    assert "( ^_^ )" in healthy_stream.getvalue()

    critical_stream = io.StringIO()
    ProgressUI("always", critical_stream).summary(
        30, [{"severity": "CRITICAL"}]
    )
    assert "\033[31m" in critical_stream.getvalue()
    assert "( x_x )" in critical_stream.getvalue()

def test_real_local_circular_import_is_detected(tmp_path):
    (tmp_path / "a.py").write_text("import b\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("import a\n", encoding="utf-8")
    r = audit(tmp_path, "--deep", "--format", "json")
    data = json.loads(r.stdout)
    assert any(f["rule_id"] == "ARCH-CIRCULAR-IMPORT" for f in data["findings"])
