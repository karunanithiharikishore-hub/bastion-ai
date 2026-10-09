"""BUG-PIPE-7: T1486 must not fire on bare substrings like "ransom" or ".enc".

Only a ransomware extension at the end of a token/path, or ransom-note wording,
should tag T1486. Benign words containing those substrings must not.
"""
from datetime import datetime, timezone

from bluecell.models import Event
from bluecell.pipeline import map_attack

T0 = datetime(2026, 9, 26, 9, 0, tzinfo=timezone.utc)


def _techs(message, file_path=None):
    e = Event(ts=T0, source="edr", host="h1", category="process",
              action="x", message=message, file_path=file_path)
    map_attack([e])
    return e.attack


def test_ransomware_protection_mentions_are_not_tagged():
    assert "T1486" not in _techs(message="Defender: ransomware protection enabled (controlled folder access)")
    assert "T1486" not in _techs(message="anti-ransomware scan completed: 0 threats")


def test_extension_prefix_in_module_name_is_not_tagged():
    assert "T1486" not in _techs(message="Loaded module foo.encoding")


def test_extension_prefix_with_suffix_is_not_tagged():
    assert "T1486" not in _techs(message="Created file report.encrypted-pdf.viewer")


def test_true_positive_extension_in_message_is_tagged():
    assert "T1486" in _techs(message="Files encrypted with extension .locked; vssadmin delete shadows /all")
    assert "T1486" in _techs(message="renamed doc.lockbit")


def test_true_positive_extension_in_file_path_is_tagged():
    assert "T1486" in _techs(message="file renamed", file_path="C:\\Users\\admin\\report.docx.locked")


def test_true_positive_ransom_note_wording_is_tagged():
    assert "T1486" in _techs(message="ransom note dropped to desktop")
    assert "T1486" in _techs(message="Your files have been encrypted. Pay to recover.")


def test_sample_ransomware_event_still_tags_t1486_and_t1490():
    techs = _techs(message="Files encrypted with extension .locked; vssadmin delete shadows /all")
    assert "T1486" in techs
    assert "T1490" in techs
