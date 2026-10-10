import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

SAMPLES = os.path.join(os.path.dirname(__file__), "..", "samples")
BENIGN_SAMPLES = os.path.join(os.path.dirname(__file__), "..", "samples_benign")
FEEDS = os.path.join(os.path.dirname(__file__), "..", "feeds")

# Tests must never touch the user's real ~/.bastion: point the run cache (and,
# once present, the run-trace store) at throwaway directories. Forced, not
# setdefault, so a developer's own BASTION_* settings cannot leak in.
import tempfile  # noqa: E402
_TEST_HOME = tempfile.mkdtemp(prefix="bastion-test-")
os.environ["BASTION_CACHE_DIR"] = os.path.join(_TEST_HOME, "cache")
os.environ["BASTION_RUNS_DIR"] = os.path.join(_TEST_HOME, "runs")
