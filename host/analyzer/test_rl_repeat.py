"""Tests for rl_repeat.py (repeatability and tracing overhead across runs).

Run:  python -m unittest discover -s host\\analyzer -v

Client logs here are synthetic, in the format rl_demo prints from 2026-11-20 on
(send and resp per request). The traced runs reuse test_rl_autopsy's hand-built
handoff trace. Expected numbers are worked out by hand in the comments.
"""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rl_repeat as rp  # noqa: E402
from test_rl_autopsy import handoff_trace  # noqa: E402


def client_log(reqs, deadline=2000, skipped=0, release_delay=29.5, summary=None, wrong=()):
    """rl_demo client output for (send_us, resp_us) pairs, flags derived from the deadline."""
    lines = [f"client 0: pid 1 priority 30, {len(reqs)} requests, work 500 us, period 7 ms "
             f"(fixed rate), deadline {deadline} us"]
    for seq, (send, resp) in enumerate(reqs, 1):
        flags = ("  LATE(send)" if send > deadline else "") + ("  LATE(resp)" if resp > deadline else "")
        flags += "  WRONG" if seq in wrong else ""
        lines.append(f"req 0:{seq:<4}  send {send:9.1f} us  resp {resp:9.1f} us{flags}")
    ls = sum(s > deadline for s, _ in reqs)
    lr = sum(r > deadline for _, r in reqs)
    ls, lr = summary or (ls, lr)
    n = len(reqs)
    lines += ["timers: TIMER_PRECISE accepted (no effect measured on this image)",
              f"releases skipped (previous request overran its period): {skipped}",
              f"functional: {n - len(wrong)}/{n} correct",
              f"deadline {deadline} us: {ls}/{n} late from send, {lr}/{n} late from release (client-measured)",
              "latency us: min 1.0  median 1.0  max 1.0",
              "response us (release -> reply): min 1.0  median 1.0  max 1.0",
              f"release delay us (scheduled release -> send, incl. timer tick rounding): "
              f"median {release_delay}  max {release_delay}"]
    return "\n".join(lines) + "\n"


def write_run(folder, scenario, rnd, traced, reqs, trace_text=None, **kw):
    name = f"{scenario}.r{rnd:02d}.{'on' if traced else 'off'}"
    Path(folder, f"{name}.meta").write_text(
        f"scenario={scenario}\nserver_mode=handoff\nhog_prio=20\noptions=\ncpus=0\n"
        f"trace={'on' if traced else 'off'}\nround={rnd}\n", encoding="utf-8")
    Path(folder, f"{name}.client.log").write_text(client_log(reqs, **kw), encoding="utf-8")
    if trace_text is not None:
        Path(folder, f"{name}.txt").write_text(trace_text, encoding="utf-8")
    return name


class ClientLogParser(unittest.TestCase):
    def test_fields_and_flags(self):
        warned = []
        c = rp.parse_client_log(client_log([(500, 520), (2500, 2600), (600, 2100)], skipped=3),
                                warned.append)
        self.assertEqual(warned, [])
        self.assertEqual((c.seqs, c.send_us, c.resp_us), ([1, 2, 3], [500, 2500, 600], [520, 2600, 2100]))
        self.assertEqual((c.late_send, c.late_resp, c.skipped, c.deadline_us), (1, 2, 3, 2000))
        self.assertEqual((c.correct, c.count, c.release_delay_p50), (3, 3, 29.5))

    def test_summary_that_disagrees_with_the_flags_is_warned(self):
        warned = []
        rp.parse_client_log(client_log([(500, 520)], summary=(1, 1)), warned.append)
        self.assertTrue(any("per-request flags count 0 / 0" in w for w in warned), warned)

    def test_wrong_reply_and_old_format(self):
        warned = []
        c = rp.parse_client_log(client_log([(500, 520), (510, 530)], wrong=(2,)), warned.append)
        self.assertEqual(c.wrong, 1)
        self.assertTrue(any("functional failure: 1/2" in w for w in warned), warned)
        warned = []
        rp.parse_client_log("req 0:1        514.5 us\n", warned.append)   # capture-3 format
        self.assertTrue(any("client built before 2026-11-20" in w for w in warned), warned)


class Names(unittest.TestCase):
    def test_hog_threads_merge_but_unnamed_threads_keep_their_tid(self):
        self.assertEqual(rp.generic("rl_demo/rl_hog3"), "rl_demo/rl_hog*")
        self.assertEqual(rp.generic("300/1"), "300/1")
        self.assertEqual(rp.generic("devb-sdmmc-bcm2712/fsys_resmgr"), "devb-sdmmc-bcm2712/fsys_resmgr")
        self.assertEqual(rp.generic("procnto-smp-instr/12"), "procnto-smp-instr/12")   # numeric tid name


class Stats(unittest.TestCase):
    def test_percentile_is_nearest_rank(self):
        self.assertEqual(rp.percentile([3, 1, 2], 50), 2)
        self.assertEqual(rp.percentile(list(range(1, 201)), 99), 198)   # ceil(0.99 * 200) = 198th
        self.assertIsNone(rp.percentile([], 50))

    def test_spread_and_overlap(self):
        self.assertEqual(rp.spread([4, None, 1, 2, 3]), {"min": 1, "median": 2.5, "max": 4, "n": 4})
        self.assertIsNone(rp.spread([None]))
        a, b, c = rp.spread([1, 2]), rp.spread([2, 3]), rp.spread([5, 6])
        self.assertEqual((rp.overlap(a, b), rp.overlap(a, c)), (True, False))


class EndToEnd(unittest.TestCase):
    """One scenario, 2 rounds, traced and untraced.

    client p50s (nearest rank of 3 = the 2nd smallest):
      off r1: resp [520, 2100, 2600] -> 2100, send [500, 600, 2500] -> 600, late resp 2
      off r2: resp [510, 530, 540]   -> 530,  send -> 510, late resp 0
      on  r1: resp [620, 2200, 2700] -> 2200, send -> 700, late resp 2
      on  r2: resp [610, 630, 640]   -> 630,  send -> 610, late resp 0
    medians across runs: resp_p50 on 1415, off 1315 -> +100; send_p50 655 vs 555 -> +100;
    late_resp 1 vs 1 -> +0. Ranges: resp_p50 on [630-2200] / off [530-2100] and late_resp
    overlap; send_p50 on [610-700] / off [510-600] do not.
    analyzer: on r1 = handoff trace with a 600 us deadline (late, priority inversion,
    rule 1, 401/409 = 98.0% of lost time); on r2 = no deadline (nothing late).
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.d = self.tmp.name
        write_run(d, "defect", 1, False, [(500, 520), (2500, 2600), (600, 2100)])
        write_run(d, "defect", 2, False, [(500, 510), (510, 530), (520, 540)])
        write_run(d, "defect", 1, True, [(600, 620), (2600, 2700), (700, 2200)],
                  trace_text=handoff_trace(deadline=600))
        write_run(d, "defect", 2, True, [(600, 610), (610, 630), (620, 640)],
                  trace_text=handoff_trace())
        Path(d, "unrelated.meta").write_text("scenario=x\ncpus=all\n", encoding="utf-8")  # not a repeat run

    def tearDown(self):
        self.tmp.cleanup()

    def test_groups_overhead_and_causes(self):
        rep = rp.build(self.d)
        self.assertEqual(rep.warnings, [])
        self.assertEqual(len(rep.runs), 4)
        on, off = rep.groups[("defect", True)], rep.groups[("defect", False)]
        self.assertEqual(on["resp_p50"], {"min": 630, "median": 1415, "max": 2200, "n": 2})
        self.assertEqual(off["late_resp"], {"min": 0, "median": 1, "max": 2, "n": 2})
        self.assertIsNone(off["late_analyzer"])                         # untraced: no analyzer
        self.assertEqual(on["late_analyzer"], {"min": 0, "median": 0.5, "max": 1, "n": 2})
        o = rep.overhead["defect"]
        self.assertEqual((o["resp_p50"]["diff"], o["send_p50"]["diff"], o["late_resp"]["diff"]),
                         (100, 100, 0))
        self.assertEqual([o[k]["overlap"] for k in ("resp_p50", "send_p50", "late_resp")],
                         [True, False, True])
        r1 = next(r for r in rep.runs if r.traced and r.round == 1)
        self.assertEqual((r1.dominant, r1.metrics["dominant_share"], r1.metrics["rule1"]),
                         ("priority inversion", 98.0, 1))
        self.assertEqual(r1.top_culprit, "300/1@20 higher")
        self.assertIsNone(r1.metrics["wake_offset_p50"])   # the only request has no kernel release
        r2 = next(r for r in rep.runs if r.traced and r.round == 2)
        self.assertEqual((r2.dominant, r2.metrics["rule1"]), ("none late", 0))

    def test_cli_table_and_json(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = rp.main([self.d, "--quiet"])
        self.assertEqual(code, 0)
        self.assertIn("defect        on        2  1 [0-2]", out.getvalue())
        self.assertIn("dominant: priority inversion 1/2, none late 1/2", out.getvalue())
        self.assertIn("resp_p50 +100.0, resp_p99 +100.0, send_p50 +100.0 (no overlap)", out.getvalue())
        js = os.path.join(self.d, "out.json")
        with contextlib.redirect_stdout(io.StringIO()):
            rp.main([self.d, "--quiet", "--json", js])
        with open(js, encoding="utf-8") as f:
            d = json.load(f)
        self.assertEqual((d["schema"], len(d["runs"]), d["warnings"]), ("resiliencelab.repeat/0", 4, []))

    def test_traced_run_without_txt_is_a_warning(self):
        os.remove(os.path.join(self.d, "defect.r02.on.txt"))
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            code = rp.main([self.d, "--quiet"])
        self.assertEqual(code, 1)
        self.assertIn("traced run has no defect.r02.on.txt", err.getvalue())

    def test_unequal_run_counts_are_a_warning(self):
        write_run(self.d, "defect", 3, False, [(500, 510)])
        self.assertIn("defect: 2 traced runs but 3 untraced", rp.build(self.d).warnings)


class Fatal(unittest.TestCase):
    def test_no_repeat_runs(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "defect.meta").write_text("scenario=defect\ncpus=all\n", encoding="utf-8")
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                self.assertEqual(rp.main([d, "--quiet"]), 2)
            self.assertIn("no repeat runs", err.getvalue())


if __name__ == "__main__":
    unittest.main()
