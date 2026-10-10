"""BUG-PIPE-9 -- T1053 needs scheduled-job creation, not any mention of a scheduled
task; T1021 must not fire on the Samba daemon smbd; T1110 must not fire on "failover"."""
from bastion.models import Event
from bastion.pipeline import map_attack


def _tags(message, category="process", action="process_create", process=None):
    e = Event(ts="2026-09-26T09:00:00Z", source="edr", host="h", category=category,
              action=action, message=message, process=process)
    map_attack([e])
    return e.attack


def test_false_positives_are_untagged():
    assert "T1053" not in _tags("Task Scheduler: scheduled task 'GoogleUpdateTaskMachineCore' "
                                "completed successfully")
    assert "T1021" not in _tags("smbd: connection from 10.0.0.9 (Samba file server)")
    assert "T1110" not in _tags("authentication failover to secondary directory",
                                category="authentication", action="auth_event")


def test_true_positives_are_still_tagged():
    assert "T1053" in _tags("Task Scheduler: scheduled task 'Updater' was created")
    assert "T1053" in _tags("schtasks /create /tn evil /tr evil.bat /sc onlogon")
    assert "T1053" in _tags("EventID=4698 A scheduled task was created")
    assert "T1021" in _tags("python smbexec.py corp/admin@10.0.0.9")
    assert "T1021" in _tags("smbclient //db02/c$")
    assert "T1110" in _tags("Failed password for root from 203.0.113.5",
                            category="authentication", action="login_failed")
    assert "T1110" in _tags("authentication failure for bob",
                            category="authentication", action="auth_event")
