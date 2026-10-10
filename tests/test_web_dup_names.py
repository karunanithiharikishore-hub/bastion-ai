# BlueCell - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BLUECELL::AUTHOR::Harikishore-Karunanithi
"""ITEM-13: same-named dropped files must stay distinct in the intake list (app.js uniqueName)."""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

APP_JS = Path(__file__).resolve().parents[1] / "src/bluecell/web/static/app.js"


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_same_named_files_get_distinct_keys():
    m = re.search(r"^function uniqueName\(name\) \{.*?^\}", APP_JS.read_text(), re.S | re.M)
    assert m, "uniqueName helper not found in app.js"
    script = (m.group(0) + "\n"
              "const pending = new Map();\n"
              "const names = ['auth.log', 'auth.log', 'auth.log', 'README', '.env', 'a.tar.gz', 'a.tar.gz'];\n"
              "const out = [];\n"
              "for (const n of names) { const k = uniqueName(n); pending.set(k, {name: k}); out.push(k); }\n"
              "console.log(JSON.stringify(out));\n")
    res = subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=20)
    assert res.returncode == 0, res.stderr
    out = json.loads(res.stdout)
    assert out == ["auth.log", "auth (2).log", "auth (3).log", "README", ".env", "a.tar.gz", "a.tar (2).gz"]
    assert len(set(out)) == len(out)
