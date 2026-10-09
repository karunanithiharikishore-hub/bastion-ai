"""BUG-PIPE-8 -- T1562 impair-defenses must not fire on cancelled scans or stopped
log/export jobs, and must still fire on a stopped Sysmon64 service."""
from bluecell.models import Event
from bluecell.pipeline import map_attack


def _tags(message):
    e = Event(ts="2026-09-26T09:00:00Z", source="edr", host="h", category="process",
              action="service_stop", message=message)
    map_attack([e])
    return e.attack


def test_scan_and_job_stops_are_not_impair_defenses():
    for m in ("Defender scan was stopped by user",
              "Antivirus scheduled scan was stopped after 2 hours",
              "Defender quick scan has been disabled in the schedule policy",
              "firewall log export job was stopped"):
        assert "T1562" not in _tags(m), m


def test_stopped_sysmon_service_is_impair_defenses():
    assert "T1562" in _tags("Sysmon64 service stopped")
    assert "T1562" in _tags("sysmon64 was stopped")
    assert "T1562" in _tags("sc stop Sysmon64")
