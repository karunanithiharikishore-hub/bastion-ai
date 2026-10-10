from bastion.ingest.loader import ingest_file


def test_unquoted_comma_in_recipient_status_is_rejoined(tmp_path):
    p = tmp_path / "MTSummary.csv"
    p.write_text("Received,Sender,Subject,Recipient_status\n"
                 "2026-01-01 10:00:00,a@x.com,hi,b@y.com##Receive, Deliver;c@y.com##Receive, Fail\n")
    (ev,) = ingest_file(str(p))
    assert "subj='hi'" in ev.message
    assert ev.raw["Recipient_status"] == "b@y.com##Receive, Deliver;c@y.com##Receive, Fail"
    assert ev.raw["Subject"] == "hi"


def test_unquoted_comma_before_later_columns_keeps_them_intact(tmp_path):
    p = tmp_path / "MTSummary.csv"
    p.write_text("Received,Sender,Recipient_status,Subject\n"
                 "2026-01-01 10:00:00,a@x.com,b@y.com##Receive, Fail,hi\n")
    (ev,) = ingest_file(str(p))
    assert ev.raw["Recipient_status"] == "b@y.com##Receive, Fail"
    assert ev.raw["Subject"] == "hi"
    assert "subj='hi'" in ev.message


def test_ragged_overflow_without_recipient_column_is_kept_not_dropped(tmp_path):
    p = tmp_path / "other.csv"
    p.write_text("timestamp,host,message\n2026-01-01T00:00:00Z,a,one,two\n")
    (ev,) = ingest_file(str(p))
    assert ev.raw["message"] == "one"
    assert ev.raw["host"] == "a"
    assert ev.raw["_overflow"] == "two"
