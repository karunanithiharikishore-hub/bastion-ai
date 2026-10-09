import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

SAMPLES = os.path.join(os.path.dirname(__file__), "..", "samples")
BENIGN_SAMPLES = os.path.join(os.path.dirname(__file__), "..", "samples_benign")
FEEDS = os.path.join(os.path.dirname(__file__), "..", "feeds")

# Keep run traces written by analyze() out of the user's ~/.bluecell/runs.
import tempfile  # noqa: E402
os.environ.setdefault("BLUECELL_RUNS_DIR", tempfile.mkdtemp(prefix="bluecell-test-runs-"))
