"""BUG-INGEST-19: parse_dns must accept the common query-name field names.

Before the fix, records using query_name / QueryName / rrname / ECS
dns.question.name returned None, so the whole DNS file was silently dropped."""
from bastion.ingest.parsers import parse_dns


def test_parse_dns_accepts_alternate_query_name_fields():
    cases = {
        "query_name": "evil.com.",
        "QueryName": "evil.com",
        "rrname": "evil.com",
        "dns.question.name": "evil.com",
    }
    for key, name in cases.items():
        ev = parse_dns({"timestamp": "2026-01-01T00:00:00Z", key: name})
        assert ev is not None, f"{key} not recognised"
        assert ev.domain == "evil.com", key
