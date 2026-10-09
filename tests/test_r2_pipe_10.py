"""BUG-PIPE-10 / BUG-FEAT-4 -- the run-cache code fingerprint must change when any
package source file changes (pipeline/, intel/, ingest/, models.py, ...), not only
the LLM-path files, so a code change never serves a stale cached result."""
import os
import shutil

import pytest

from bluecell import cache

PKG = os.path.dirname(cache.__file__)


@pytest.fixture
def pkg_copy(tmp_path, monkeypatch):
    dst = tmp_path / "bluecell"
    shutil.copytree(PKG, dst, ignore=shutil.ignore_patterns("__pycache__"))
    monkeypatch.setattr(cache, "_PKG_DIR", str(dst))
    return dst


def test_fingerprint_is_stable_for_unchanged_code(pkg_copy):
    assert cache.code_fingerprint() == cache.code_fingerprint()


@pytest.mark.parametrize("rel", [
    "pipeline/compress.py",     # digest text in the prompt
    "pipeline/correlate.py",    # incident grouping and severity labels
    "pipeline/ioc.py",          # IOC checklists in case_overview
    "intel/store.py",           # threat-intel retrieval
    "models.py",                # normalized event model
    "ingest/parsers.py",
    "agents/budget.py",         # already covered; must stay covered
])
def test_code_change_in_any_package_file_changes_fingerprint(pkg_copy, rel):
    before = cache.code_fingerprint()
    target = pkg_copy / rel
    target.write_text(target.read_text(encoding="utf-8") + "\n# changed\n", encoding="utf-8")
    assert cache.code_fingerprint() != before


def test_new_source_file_changes_fingerprint(pkg_copy):
    before = cache.code_fingerprint()
    (pkg_copy / "pipeline" / "new_module.py").write_text("X = 1\n", encoding="utf-8")
    assert cache.code_fingerprint() != before
