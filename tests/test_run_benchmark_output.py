"""Regression tests: the benchmark's printed summary must reflect real results.

Before the fix, run_benchmark.py printed a hard-coded "(100.0%)", "ZERO EXECUTION" and a
"565/565 BLOCKED" VERDICT even when attacks were allowed. These tests feed fake suite
results with failures and check the output and exit code tell the truth.
"""

import contextlib
import io
import sys
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "scripts"))

from benchmark import run_benchmark  # noqa: E402


def _fake(attempts, denied, benign, allowed):
    """Shape of the dict returned by the suites' run() functions."""
    return {"attempts": attempts, "attempts_denied": denied, "benign": benign, "benign_allowed": allowed}


class TestBenchmarkOutput(unittest.TestCase):
    """Output and exit code are derived from the counts, not fixed strings."""

    def _run_main(self, primary, heldout):
        """Run main(--mode user) with patched suites; return (exit_code, stdout)."""
        buf = io.StringIO()
        with mock.patch.object(run_benchmark.bypass_suite, "run", return_value=primary), \
                mock.patch.object(run_benchmark.heldout_suite, "run", return_value=heldout), \
                mock.patch.object(sys, "argv", ["run_benchmark", "--mode", "user"]), \
                contextlib.redirect_stdout(buf):
            code = run_benchmark.main()
        return code, buf.getvalue()

    def test_failure_is_reported_honestly(self):
        """A leaked attack must lower the percentage, drop the ZERO EXECUTION claim and exit 1."""
        code, out = self._run_main(_fake(100, 90, 10, 10), _fake(10, 10, 5, 5))
        self.assertEqual(code, 1)
        self.assertNotIn("ZERO EXECUTION", out)
        self.assertNotIn("ZERO DANGEROUS COMMANDS EXECUTED", out)
        self.assertIn("100/110 (90.9%)", out)
        self.assertIn("VERDICT: FAIL", out)

    def test_success_keeps_the_clean_banner(self):
        """With every attack denied the clean banner and exit code 0 are produced."""
        code, out = self._run_main(_fake(100, 100, 10, 10), _fake(10, 10, 5, 5))
        self.assertEqual(code, 0)
        self.assertIn("(100.0%)", out)
        self.assertIn("ZERO EXECUTION", out)
        self.assertIn("110/110 ADVERSARIAL ATTACKS BLOCKED", out)

    def test_verdict_line_flags_wrongly_denied_benign(self):
        """Blocking a benign command is also a failure (the gate checks both directions)."""
        self.assertIn("FAIL", run_benchmark.verdict_line(5, 5, 4, 3))


if __name__ == "__main__":
    unittest.main()
