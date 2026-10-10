"""ITEM-21: Elasticsearch hits (`_source`) and Splunk exports (`result`/`results`) must ingest as events."""
import json

from bastion.ingest.loader import ingest_file

SRC = {"@timestamp": "2026-10-03T22:00:00Z", "host": {"name": "DC01"}, "user": {"name": "admin"},
       "source": {"ip": "203.0.113.9"}, "event": {"action": "logon-failed"},
       "message": "An account failed to log on."}


def _write(tmp_path, name, obj):
    p = tmp_path / name
    p.write_text(obj if isinstance(obj, str) else json.dumps(obj))
    return str(p)


def test_es_search_response_hits_unwrap_to_events(tmp_path):
    body = {"took": 3, "hits": {"total": {"value": 2}, "hits": [
        {"_index": "winlogbeat", "_id": "1", "_source": SRC},
        {"_index": "winlogbeat", "_id": "2", "_source": SRC}]}}
    evs = ingest_file(_write(tmp_path, "es.json", body))
    assert len(evs) == 2
    assert all(e.action == "login_failed" and e.host == "DC01" for e in evs)


def test_es_hit_per_jsonl_line_and_bare_hit_list(tmp_path):
    hit = {"_index": "winlogbeat", "_id": "1", "_source": SRC}
    assert len(ingest_file(_write(tmp_path, "kibana.jsonl", json.dumps(hit) + "\n"))) == 1
    assert len(ingest_file(_write(tmp_path, "hits.json", [hit, hit]))) == 2


def test_splunk_result_line_maps_time_and_raw(tmp_path):
    line = {"preview": False, "offset": 0, "result": {
        "_time": "2026-10-03T22:00:00.000+00:00", "host": "DC01", "source": "WinEventLog:Security",
        "_raw": "EventCode=4625 Account_Name=admin Source_Network_Address=203.0.113.9"}}
    evs = ingest_file(_write(tmp_path, "splunk.json", json.dumps(line) + "\n"))
    assert len(evs) == 1
    assert evs[0].host == "DC01"
    assert evs[0].ts.isoformat().startswith("2026-10-03T22:00:00")
    assert "EventCode=4625" in evs[0].message


def test_splunk_results_list_unwraps(tmp_path):
    row = {"_time": "2026-10-03T22:00:00.000+00:00", "host": "DC01", "_raw": "EventCode=4625"}
    evs = ingest_file(_write(tmp_path, "results.json", {"results": [row, row]}))
    assert len(evs) == 2
    assert all("EventCode=4625" in e.message for e in evs)
