"""BUG-INGEST-11: only "\n" separates records; U+2028/U+0085/\x0c inside a
line must not create a new syslog event (log forging) or drop JSONL records."""
import json
import pytest

from bluecell.ingest.loader import ingest_file


@pytest.mark.parametrize("sep", [" ", "\u0085", "\x0c", "\x1c", "\x0b"])
def test_syslog_line_with_unicode_separator_is_one_event(tmp_path, sep):
    p = tmp_path / "auth.log"
    p.write_text(
        "Oct  3 22:00:00 h sshd[1]: Accepted password for bob from 1.1.1.1"
        + sep
        + "Oct  3 22:00:01 h sshd[1]: Failed password for root from 2.2.2.2\n",
        encoding="utf-8")
    evs = ingest_file(str(p))
    assert len(evs) == 1   # the embedded second half must not become its own event
    assert sep in evs[0].message


def test_jsonl_with_raw_u2028_in_string_keeps_both_records(tmp_path):
    p = tmp_path / "u.jsonl"
    a = {"timestamp": "2026-01-01T00:00:00Z", "host": "a", "message": "x y"}
    b = {"timestamp": "2026-01-01T00:00:00Z", "host": "b", "message": "ok"}
    p.write_text(json.dumps(a, ensure_ascii=False) + "\n" + json.dumps(b) + "\n",
                 encoding="utf-8")
    assert [e.host for e in ingest_file(str(p))] == ["a", "b"]
