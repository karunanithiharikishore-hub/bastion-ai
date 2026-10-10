"""Bastion AI was renamed from BlueCell: old settings and data must keep working."""
import os
import subprocess
import sys

SRC = os.path.join(os.path.dirname(__file__), "..", "src")


def _env_after_import(env):
    code = "import bastion, os, json; print(json.dumps({k: v for k, v in os.environ.items() if k.startswith('BASTION_')}))"
    out = subprocess.run([sys.executable, "-c", code], env=dict(env, PYTHONPATH=SRC),
                         capture_output=True, text=True, check=True).stdout
    import json
    return json.loads(out)


def test_old_bluecell_env_vars_still_work(tmp_path):
    env = {k: v for k, v in os.environ.items() if not k.startswith(("BASTION_", "BLUECELL_"))}
    env.update(HOME=str(tmp_path), BLUECELL_RUNS_DIR="/x/runs")
    assert _env_after_import(env)["BASTION_RUNS_DIR"] == "/x/runs"


def test_new_env_wins_over_old(tmp_path):
    env = {k: v for k, v in os.environ.items() if not k.startswith(("BASTION_", "BLUECELL_"))}
    env.update(HOME=str(tmp_path), BLUECELL_RUNS_DIR="/old", BASTION_RUNS_DIR="/new")
    assert _env_after_import(env)["BASTION_RUNS_DIR"] == "/new"


def test_existing_bluecell_data_dir_is_reused(tmp_path):
    (tmp_path / ".bluecell" / "runs").mkdir(parents=True)
    env = {k: v for k, v in os.environ.items() if not k.startswith(("BASTION_", "BLUECELL_"))}
    env["HOME"] = str(tmp_path)
    assert _env_after_import(env)["BASTION_RUNS_DIR"] == str(tmp_path / ".bluecell" / "runs")
