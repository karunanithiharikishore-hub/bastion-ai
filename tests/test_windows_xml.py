"""Windows event XML (Save as XML / wevtutil /f:xml) is parsed as EDR events; DOCTYPE/ENTITY is refused."""
from bastion.ingest.loader import ingest_file
from bastion.pipeline.attack import map_attack

NS = 'xmlns="http://schemas.microsoft.com/win/2004/08/events/event"'


def _event(i):
    return (f'<Event {NS}><System><Provider Name="Microsoft-Windows-Security-Auditing"/>'
            f'<EventID>4625</EventID><TimeCreated SystemTime="2026-10-03T22:0{i}:00.1234567Z"/>'
            f'<Computer>DC01.corp.local</Computer><Channel>Security</Channel></System>'
            f'<EventData><Data Name="TargetUserName">admin</Data>'
            f'<Data Name="IpAddress">203.0.113.5</Data><Data Name="LogonType">3</Data></EventData></Event>')


def test_six_failed_4625_from_one_ip_is_t1110(tmp_path):
    p = tmp_path / "security.xml"
    p.write_text(f'<?xml version="1.0"?><Events>{"".join(_event(i) for i in range(6))}</Events>')
    evs = map_attack(ingest_file(str(p)))
    assert len(evs) == 6
    for e in evs:
        assert (e.category, e.host, e.user, e.src_ip) == ("authentication", "DC01.corp.local", "admin", "203.0.113.5")
        assert "T1110" in str(e.attack)


def test_doctype_entity_file_is_refused(tmp_path, capsys):
    bomb = ('<?xml version="1.0"?><!DOCTYPE Events [<!ENTITY a "aaaaaaaaaa">'
            '<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]>'
            f'<Events>{_event(0)}<Event {NS}><EventID>&b;</EventID></Event></Events>')
    p = tmp_path / "bomb.xml"
    p.write_text(bomb)
    assert ingest_file(str(p)) == []
    assert "refused" in capsys.readouterr().err


def test_directory_walk_ingests_cef_files(tmp_path):
    from bastion.ingest import ingest_path
    (tmp_path / "fw.cef").write_text(
        "Oct 05 02:31:00 fw01 CEF:0|PaloAlto|PAN-OS|10.2|TRAFFIC|end|3|src=10.20.1.15 dst=203.0.113.77 dpt=443 act=allow\n")
    evs = ingest_path(str(tmp_path))
    assert len(evs) == 1 and evs[0].dst_ip == "203.0.113.77"
