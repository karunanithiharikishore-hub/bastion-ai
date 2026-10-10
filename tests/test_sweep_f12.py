"""ITEM-12: the default intel store must not depend on a source checkout.

The old DEFAULT_PATH pointed four levels above the module (the repo's data/
dir), which does not exist for a wheel install. The default is now
$BLUECELL_INTEL_DB or ~/.bluecell/intel.json. Nothing here saves, so the repo's
data/intel.json is never touched.
"""
import os

from bluecell.intel.store import IntelStore


def test_default_store_is_under_home_when_no_override(tmp_path, monkeypatch):
    monkeypatch.delenv("BLUECELL_INTEL_DB", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    import bluecell.intel.store as store
    monkeypatch.setattr(store, "_LEGACY_PATH", str(tmp_path / "missing.json"))
    assert IntelStore().path == os.path.join(str(tmp_path), ".bluecell", "intel.json")


def test_env_override_sets_default_store(tmp_path, monkeypatch):
    target = str(tmp_path / "custom.json")
    monkeypatch.setenv("BLUECELL_INTEL_DB", target)
    assert IntelStore().path == target


def test_explicit_path_still_wins(tmp_path, monkeypatch):
    monkeypatch.setenv("BLUECELL_INTEL_DB", str(tmp_path / "env.json"))
    explicit = str(tmp_path / "explicit.json")
    assert IntelStore(explicit).path == explicit


def test_existing_checkout_store_is_still_used(tmp_path, monkeypatch):
    from bluecell.intel import store
    legacy = tmp_path / "intel.json"
    legacy.write_text('{"entries": {}}')
    monkeypatch.delenv(store.INTEL_ENV, raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setattr(store, "_LEGACY_PATH", str(legacy))
    assert store.default_path() == str(legacy)
