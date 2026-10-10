"""CEF lines inside a syslog frame keep the frame's timestamp and host."""
from bastion.ingest.parsers import parse_text_line


def test_cef_in_syslog_frame_keeps_ts_and_host():
    ev = parse_text_line("Oct 05 02:31:00 fw01 CEF:0|PaloAlto|PAN-OS|10.2|TRAFFIC|end|3|"
                         "src=10.20.1.15 dst=203.0.113.77 spt=51544 dpt=443 act=allow", {})
    assert ev.host == "fw01" and ev.source == "firewall"
    assert "ts-unparsed" not in (ev.tags or []) and ev.ts.month == 10 and ev.ts.day == 5 and ev.ts.hour == 2


def test_cef_rt_wins_over_frame():
    ev = parse_text_line("Oct 05 02:31:00 fw01 CEF:0|V|P|1|1|n|3|rt=2026-10-01T10:00:00Z src=10.0.0.1", {})
    assert ev.ts.day == 1 and ev.ts.hour == 10
