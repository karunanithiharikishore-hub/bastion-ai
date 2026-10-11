# Bastion AI - Blue-Team Log Intelligence
# Author: Harikishore Karunanithi | SPDX-License-Identifier: MIT
# WATERMARK: BASTION::AUTHOR::Harikishore-Karunanithi
"""Rules-only analysis of a large synthetic Entra sign-in export must stay fast."""
import csv
import os
import time
import uuid

import pytest

from bastion.analyzer import analyze

pytestmark = pytest.mark.skipif(os.environ.get("BASTION_SKIP_PERF") == "1",
                                reason="BASTION_SKIP_PERF=1")

COLS = ["Date (UTC)", "Request ID", "User agent", "Correlation ID", "User ID", "User", "Username",
        "Authentication Protocol", "Unique token identifier", "Application", "Resource",
        "IP address", "Location", "Status", "Sign-in error code", "Failure reason", "Client app",
        "Device ID"]


def test_50k_rows_rules_only(tmp_path):
    p = tmp_path / "signins.csv"
    with open(p, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(COLS)
        for i in range(50_000):
            fail = i % 7 == 0
            w.writerow([f"2026-10-01T{i // 3600 % 24:02d}:{i // 60 % 60:02d}:{i % 60:02d}Z",
                        uuid.uuid4(), "Mozilla/5.0", uuid.uuid4(), uuid.uuid4(), f"User {i % 300}",
                        f"u{i % 300}@example.test", "OAuth2", uuid.uuid4().hex[:22], "Office 365",
                        "Graph", f"198.51.100.{i % 250}", "US", "Failure" if fail else "Success",
                        50126 if fail else 0, "Invalid password" if fail else "", "Browser", ""])
    t = time.perf_counter()
    result = analyze([str(p)], use_llm=False, mode="quick", trace=False)
    assert time.perf_counter() - t < 20
    assert result["incidents"]
