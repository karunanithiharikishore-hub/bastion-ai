from bastion.ingest.loader import ingest_file
from bastion.ingest.parsers import parse_o365_message


def test_failed_second_recipient_raises_severity():
    ev = parse_o365_message({
        "Received": "2026-01-01 10:00:00", "Sender": "a@x.com", "Subject": "hi",
        "Recipient_status": "b@y.com##Receive, Deliver;c@y.com##Receive, Fail",
    })
    assert ev.severity == 2


def test_failed_second_recipient_raises_severity_via_loader(tmp_path):
    p = tmp_path / "MTSummary.csv"
    p.write_text("Received,Sender,Subject,Recipient_status\n"
                 "2026-01-01 10:00:00,a@x.com,hi,b@y.com##Receive, Deliver;c@y.com##Receive, Fail\n")
    (ev,) = ingest_file(str(p))
    assert ev.severity == 2
    assert "subj='hi'" in ev.message
