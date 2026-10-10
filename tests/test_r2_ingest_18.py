import json

from bastion.ingest.loader import ingest_file

TS = "2026-01-01T00:00:00Z"


def _write(tmp_path, name, obj):
    p = tmp_path / name
    p.write_text(json.dumps(obj))
    return str(p)


def test_single_event_with_list_field_keeps_its_own_fields(tmp_path):
    path = _write(tmp_path, "edr3.json",
                  {"timestamp": TS, "host": "a", "user": "bob", "data": [{"x": 1}]})
    evs = ingest_file(path)
    assert len(evs) == 1
    assert evs[0].host == "a" and evs[0].user == "bob"
    assert evs[0].ts.year == 2026


def test_envelope_with_metadata_still_unwraps(tmp_path):
    path = _write(tmp_path, "signins_graph.json", {
        "@odata.context": "x", "@odata.count": 1,
        "value": [{"createdDateTime": TS, "userPrincipalName": "a@b", "ipAddress": "1.2.3.4"}]})
    evs = ingest_file(path)
    assert len(evs) == 1 and evs[0].user == "a@b"


def test_records_wrapper_still_unwraps(tmp_path):
    path = _write(tmp_path, "ct.json", {"Records": [
        {"eventTime": TS, "eventName": "ConsoleLogin", "sourceIPAddress": "1.2.3.4"}]})
    evs = ingest_file(path)
    assert len(evs) == 1 and evs[0].ts.year == 2026
