"""Tests for rl_autopsy.py (where a request's time went).

Run:  python -m unittest discover -s host\\analyzer -v

The hand-built trace below is synthetic (not a measurement). Every bucket is
worked out by hand in the comments, so the expected values are a spec, not a
copy of the output. The invariant tests check the one property everything else
relies on: each view's buckets add up EXACTLY to the request's interval.
"""
import functools
import io
import json
import os
import random
import re
import sys
import tempfile
import unittest
from collections import Counter
from fractions import Fraction
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rl_analyze as rl  # noqa: E402
import rl_autopsy as ap  # noqa: E402
from test_rl_analyze import HEADER, START, PROBE, REPO, ev, mark, th, run_main  # noqa: E402

C, S, W, H, K = (100, 1), (200, 1), (200, 2), (300, 1), (1, 6)   # client, server, worker, hog, ISR


def handoff_trace(hog_prio=20, worker_prio=10, deadline=0):
    """One request with a handoff, all chain activity on CPU 0 (1 tick = 1 us).
    The comments below are for the defaults (worker at 10, hog at 20, no deadline).

    Holder by phase (no release: the request starts at marker 100, t=20):
      [20,30)   server S:  [20,22) blocked:THRECEIVE, [22,30) running (8)
      [30,934)  worker W@10: [30,31) blocked:THCONDVAR; READY [31,434) (403):
                  CPU0 runs S@30 [31,32) -> higher 1, nobody [32,33) -> switching 1,
                  hog H [33,433) -> 400 (higher at 20, equal at 10), nobody [433,434) -> switching 1;
                running [434,934) (500)
      [934,940) client C@30: [934,935) blocked:THREPLY; READY [935,937):
                  CPU0 runs W@10 [935,936) -> lower 1, nobody [936,937) -> switching 1;
                running [937,940) (3)
      total 920 = send. CPU 1: idle, except ISR thread K runs [100,150), nobody [150,151).
    """
    wp = worker_prio
    e = [
        th(1, 1, "THRUNNING", 1, 2, 0),            # idle_cpu_1 on CPU 1
        th(2, 1, "THINTR", *K, 255),               # K waits for interrupts: an ISR thread
        th(5, 0, "THRECEIVE", *S, 10), th(6, 0, "THCONDVAR", *W, wp),
        th(10, 0, "THRUNNING", *C, 30), mark(20, 0, 100, 1, deadline), th(21, 0, "THREPLY", *C, 30),
        th(22, 0, "THRUNNING", *S, 30), mark(30, 0, 101, 1, 30),
        th(31, 0, "THREADY", *W, wp), th(32, 0, "THRECEIVE", *S, 30),
        th(33, 0, "THRUNNING", *H, hog_prio),
        th(100, 1, "THRUNNING", *K, 255), th(150, 1, "THINTR", *K, 255), th(151, 1, "THRUNNING", 1, 2, 0),
        th(433, 0, "THNANOSLEEP", *H, hog_prio), th(434, 0, "THRUNNING", *W, wp),
        mark(934, 0, 102, 1, wp),
        th(935, 0, "THREADY", *C, 30), th(936, 0, "THCONDVAR", *W, wp), th(937, 0, "THRUNNING", *C, 30),
        mark(940, 0, 103, 1),
    ]
    return START + "".join(e)


def autopsy(text, cpus):
    res = rl.analyze(io.StringIO(text), "<synthetic>")
    rl.run_autopsy(res, cpus, "test")
    return res


NOT_READY = {"running": 511, "blocked:THRECEIVE": 2, "blocked:THCONDVAR": 1, "blocked:THREPLY": 1}


class HandBuilt(unittest.TestCase):
    def test_one_cpu_every_bucket(self):
        r = autopsy(handoff_trace(), [0]).rows[0]
        a = r.autopsy
        self.assertEqual(dict(a.split.buckets),
                         {**NOT_READY, "higher": 401, "switching": 3, "lower": 1})
        self.assertEqual(a.split.total(), r.total)           # 920: exact
        self.assertEqual(a.split.culprits[(300, 1, 20, "higher")], 400)
        self.assertEqual(a.split.culprits[(200, 2, 10, "lower")], 1)
        self.assertEqual(a.ready, {"work": 403, "reply": 2})
        # One CPU: the views agree, except that the own view calls the "lower" tick
        # a wake-up switch (see WakeupSwitch).
        own = dict(a.own.buckets)
        own["lower"] = own.pop(ap.WAKEUP)
        self.assertEqual(own, dict(a.split.buckets))

    def test_equal_priority_load(self):
        a = autopsy(handoff_trace(hog_prio=10), [0]).rows[0].autopsy
        self.assertEqual((a.split.buckets["equal"], a.split.buckets["higher"]), (400, 1))

    def test_split_across_two_cpus_is_exact_halves(self):
        a = autopsy(handoff_trace(), [0, 1]).rows[0].autopsy
        # CPU 0's half as above; CPU 1's half of the 405 READY ticks:
        # idle 69 + 283 + 2 = 354, interrupt 50, switching 1.
        half = Fraction(1, 2)
        self.assertEqual(dict(a.split.buckets),
                         {**NOT_READY, "higher": 401 * half, "lower": 1 * half,
                          "switching": (3 + 1) * half, "idle core": 354 * half, "interrupt": 50 * half})
        self.assertEqual(a.split.total(), 920)

    def test_own_cpu_view_follows_the_cpu_that_made_it_ready(self):
        a = autopsy(handoff_trace(), [1]).rows[0].autopsy
        # Allowed CPU 1 only: the split view sees just CPU 1 ...
        self.assertEqual(dict(a.split.buckets),
                         {**NOT_READY, "idle core": 354, "interrupt": 50, "switching": 1})
        # ... but both THREADY events were logged on CPU 0, so the own view charges CPU 0.
        self.assertEqual(dict(a.own.buckets), {**NOT_READY, "higher": 401, "switching": 3, ap.WAKEUP: 1})
        self.assertEqual(a.own.total(), a.split.total())

    def test_names_come_from_continuation_lines(self):
        names = ("t:0x3 CPU:00 PROCESS         :PROCCREATE_NAME   \n"
                 "                      ppid:1\n                       pid:300\n"
                 "                      name:data/home/qnxuser/bin/rl_demo\n"
                 "t:0x4 CPU:00 PROCESS         :PROCTHREAD_NAME   \n"
                 "                       pid:300\n                       tid:1\n"
                 "                      name:rl_hog0\n")
        text = START + names + handoff_trace()[len(START):]
        res = autopsy(text, [0])
        self.assertEqual(res.timeline.name(H), "rl_demo/rl_hog0")
        self.assertEqual(res.timeline.name(C), "100/1")          # unnamed: pid/tid
        # Line numbers unchanged by attaching continuation lines (computed, not hand-counted).
        self.assertEqual(res.rows[0].m[100].lineno,
                         text.splitlines().index(mark(20, 0, 100, 1).rstrip("\n")) + 1)


def late_arrival_trace():
    """handoff_trace, but after W blocks at 936 the hog H@20 takes CPU 0 until 938
    (instead of 'switching' at [936,937) and C running from 937)."""
    text = handoff_trace()
    old = th(937, 0, "THRUNNING", *C, 30)
    assert old in text
    return text.replace(old, th(936, 0, "THRUNNING", *H, 20) + th(938, 0, "THRUNNING", *C, 30))


class WakeupSwitch(unittest.TestCase):
    """Own view: a lower-priority share is a "wake-up switch" when the thread is the one
    that was already running on the holder's CPU when the THREADY was logged, and has
    not left since. Any other lower-priority thread stays "lower" (not migrated)."""

    def test_replier_finishing_its_reply_is_a_wakeup_switch(self):
        # [935,936): W@10's MsgReply readied C@30 on CPU 0 (THREADY at 935, CPU 0), and W
        # still runs there until 936. Own view: wake-up switch. Split view: still "lower".
        a = autopsy(handoff_trace(deadline=600), [0]).rows[0].autopsy
        self.assertEqual((a.own.buckets[ap.WAKEUP], a.own.buckets["lower"]), (1, 0))
        self.assertEqual(a.own.culprits, {(300, 1, 20, "higher"): 400, (200, 1, 30, "higher"): 1,
                                          (200, 2, 10, ap.WAKEUP): 1})
        self.assertEqual((a.split.buckets["lower"], a.split.buckets[ap.WAKEUP]), (1, 0))
        self.assertEqual(a.cause.by_cause, causes(**{INV: 401, WAKE: 1, OTHER: 7}))
        self.assertEqual(a.cause_split.by_cause, causes(**{INV: 401, NOTMIG: 1, OTHER: 7}))

    def test_a_thread_that_arrives_after_the_wakeup_is_not_migrated(self):
        # [935,936) W, the thread there at the wake-up: wake-up switch 1.
        # [936,938) H@20 was dispatched after the wake-up: lower 2 -> not migrated.
        r = autopsy(late_arrival_trace(), [0]).rows[0]
        a = r.autopsy
        self.assertEqual(dict(a.own.buckets),
                         {**NOT_READY, "running": 510, "higher": 401, "switching": 2,
                          ap.WAKEUP: 1, "lower": 2})
        self.assertEqual(a.own.culprits[(300, 1, 20, "lower")], 2)
        self.assertEqual((a.cause.by_cause[WAKE], a.cause.by_cause[NOTMIG]), (1, 2))
        self.assertEqual(a.own.total(), r.total)

    def test_priority_drop_after_reply_is_still_the_same_stay(self):
        # rl_demo's inherit mode: the worker replies at 30, then SchedSet()s back to 10.
        # The kernel logs that as a new THRUNNING for the same thread on the same CPU
        # (seen in capture 3 fixed.txt, line ~100925), not a context switch.
        # [935,936) W@30 = C's 30 -> equal; [936,937) W@10 -> wake-up switch.
        text = handoff_trace(worker_prio=30, hog_prio=30)
        old = th(936, 0, "THCONDVAR", *W, 30) + th(937, 0, "THRUNNING", *C, 30)
        self.assertIn(old, text)
        text = text.replace(old, th(936, 0, "THRUNNING", *W, 10) + th(937, 0, "THCONDVAR", *W, 10)
                            + th(938, 0, "THRUNNING", *C, 30))
        r = autopsy(text, [0]).rows[0]
        a = r.autopsy
        self.assertEqual((a.own.buckets[ap.WAKEUP], a.own.buckets["lower"]), (1, 0))
        self.assertEqual(a.own.culprits[(200, 2, 10, ap.WAKEUP)], 1)
        self.assertEqual(a.split.buckets["lower"], 1)               # split view: still "lower"
        self.assertEqual(a.own.total(), r.total)

    def test_json_and_table_name_it(self):
        _, out, _ = run_main(handoff_trace(deadline=600), "--json", "-")
        own = json.loads(out)["requests"][0]["autopsy"]["views"]["own"]
        self.assertEqual(own["buckets"][ap.WAKEUP], {"ticks": 1, "us": 1.0})
        self.assertIn({"pid": 200, "tid": 2, "prio": 10, "name": "200/2", "label": ap.WAKEUP,
                       "ticks": 1, "us": 1.0}, own["culprits"])
        _, out, _ = run_main(handoff_trace(deadline=600))
        self.assertIn("wake-up switch 0.2% [0.0%]", out)
        self.assertIn("not migrated 0.0% [0.1%]", out)


INV, LOAD, OVER, NOTMIG, WAKE, OTHER = (ap.INVERSION, ap.LOAD, ap.OVERLOAD, ap.NOT_MIGRATED,
                                        ap.WAKEUP, ap.OTHER)


def causes(**kw):
    return {INV: 0, LOAD: 0, OVER: 0, NOTMIG: 0, WAKE: 0, OTHER: 0, **kw}


class Causes(unittest.TestCase):
    """Cause of the lost time (920 - 511 running = 409 ticks), own-CPU view first.

    Default trace, one CPU: higher 401 = hog@20 400 + S@30 1, both at or below the
    client's 30 -> inversion. W@10 still running 1 tick after its reply readied C -> wake-up switch.
    switching 3 + blocked 4 -> other.
    """

    def row(self, cpus=(0,), **kw):
        return autopsy(handoff_trace(**kw), list(cpus)).rows[0]

    def test_rule1_handoff_below_client(self):
        r = self.row(deadline=600)
        c = r.autopsy.cause
        self.assertTrue(r.late)
        self.assertEqual((c.lost, c.by_cause), (409, causes(**{INV: 401, WAKE: 1, OTHER: 7})))
        self.assertEqual((c.name, c.share, c.rule), (INV, Fraction(401, 409), ap.RULE1))

    def test_equal_priority_below_the_client_is_still_inversion(self):
        # Hog@10 ties with the worker@10, but the client is at 30: with inheritance
        # the worker would have won, so this is inversion, not overload.
        c = self.row(hog_prio=10, deadline=600).autopsy.cause
        self.assertEqual((c.name, c.by_cause[INV], c.rule), (INV, 401, ap.RULE1))

    def test_above_the_client_is_load(self):
        c = self.row(hog_prio=40, deadline=600).autopsy.cause
        self.assertEqual(c.by_cause, causes(**{LOAD: 400, INV: 1, WAKE: 1, OTHER: 7}))
        self.assertEqual((c.name, c.rule), (LOAD, None))

    def test_same_priority_overload_is_not_inversion(self):
        # The negative control's shape: worker at the client's 30, hog at 30.
        # S@30 1 + hog 400 + W@30 1 (equal now, not lower) = 402 overload.
        r = self.row(worker_prio=30, hog_prio=30, deadline=600)
        c = r.autopsy.cause
        self.assertTrue(rl.handoff(r))                       # still a handoff, but not below
        self.assertEqual(c.by_cause, causes(**{OVER: 402, OTHER: 7}))
        self.assertEqual((c.name, c.rule), (OVER, None))

    def test_split_view_is_context_only(self):
        # Two CPUs: own view unchanged; the split view halves every READY share,
        # so inversion is 200.5 / 409 = 49% there, and "other" (mostly idle CPU 1's
        # half: 177 idle + 25 interrupt + 2 switching + 4 blocked = 208) is 50.9%.
        a = self.row(cpus=(0, 1), deadline=600).autopsy
        self.assertEqual((a.cause.name, a.cause.share), (INV, Fraction(401, 409)))
        self.assertEqual(a.cause_split.by_cause, causes(**{INV: Fraction(401, 2), NOTMIG: Fraction(1, 2),
                                                           OTHER: 208}))
        self.assertEqual((a.cause_split.name, a.cause_split.share), (OTHER, Fraction(208, 409)))

    def test_service_time_when_running_alone_misses_the_deadline(self):
        c = self.row(deadline=400).autopsy.cause                 # running 511 >= 400
        self.assertEqual((c.name, c.share, c.top), (ap.SERVICE, Fraction(511, 920), INV))

    def test_mixed_below_half_named_at_half(self):
        def view(inv):
            v = ap.View()
            v.culprits.update({(1, 1, 20, "higher"): inv, (2, 1, 30, "equal"): 30})
            return v
        mixed = ap.classify(view(40), 100, 30, None, True)      # 40 / 30 / other 30
        self.assertEqual((mixed.name, mixed.top, mixed.share, mixed.rule), (ap.MIXED, INV, Fraction(2, 5), None))
        half = ap.classify(view(50), 100, 30, None, True)       # exactly 50% "reaches" it
        self.assertEqual((half.name, half.rule), (INV, ap.RULE1))

    def test_unknown_client_priority_is_other(self):
        v = ap.View()
        v.culprits[(1, 1, 20, "higher")] = 60
        self.assertEqual(ap.classify(v, 100, None, None, False).by_cause, causes(**{OTHER: 100}))


class Output(unittest.TestCase):
    """run_main has no .meta, so it uses both of the header's CPUs."""

    def test_summary_and_per_request_line(self):
        code, out, _ = run_main(handoff_trace(deadline=600), "--autopsy")
        self.assertEqual(code, 0)
        self.assertIn("autopsy: 1 late requests, own-CPU view [split view]; cpus 0-1 (default: all cores)", out)
        self.assertIn(f"causes:    priority inversion 1; 1 of them {ap.RULE1}  [split: other 1]", out)
        self.assertIn("priority inversion 98.0% [49.0%]", out)
        self.assertIn("culprits:  300/1@20 higher 400.0 us, ", out)   # own view; unnamed: pid/tid
        self.assertIn(f"0:1     send 920.0 us, lost 409.0 us: priority inversion 98% ({ap.RULE1}); "
                      f"top 300/1@20 higher 400.0 us  [split: other 51%]", out)

    def test_no_late_requests(self):
        _, out, _ = run_main(handoff_trace(), "--autopsy")
        self.assertIn("autopsy: no late requests; cpus 0-1", out)
        self.assertIn("holder READY time over 1 completed requests: mean 405.0 us, max 405.0 us", out)

    def test_json_v1(self):
        _, out, _ = run_main(handoff_trace(deadline=600), "--json", "-")
        d = json.loads(out)
        self.assertEqual(d["schema"], "resiliencelab.analyze/1")
        a = d["requests"][0]["autopsy"]
        self.assertEqual((a["cause"]["name"], a["cause"]["rule"]), (INV, ap.RULE1))
        self.assertEqual(sum(x["ticks"] for x in a["cause"]["by_cause"].values()), a["cause"]["lost"]["ticks"])
        self.assertEqual(a["views"]["split"]["buckets"]["higher"], {"ticks": 200.5, "us": 200.5})
        self.assertEqual(a["views"]["own"]["culprits"][0],
                         {"pid": 300, "tid": 1, "prio": 20, "name": "300/1", "label": "higher",
                          "ticks": 400, "us": 400.0})
        self.assertEqual(a["not_migrated"]["ticks"], 0.5)
        s = d["autopsy"]
        self.assertEqual((s["primary_view"], s["late"], s["causes"], s["rules"]),
                         ("own", 1, {INV: 1}, {ap.RULE1: 1}))


class CpuSet(unittest.TestCase):
    HDR = {"TRACE_CPU_NUM": "4"}

    def test_precedence(self):
        with tempfile.TemporaryDirectory() as d:
            trace = os.path.join(d, "defect_cpu0.txt")
            self.assertEqual(rl.resolve_cpus(None, trace, self.HDR), ([0, 1, 2, 3], "default: all cores"))
            Path(d, "defect_cpu0.meta").write_text("scenario=defect_cpu0\ncpus=0\n", encoding="utf-8")
            self.assertEqual(rl.resolve_cpus(None, trace, self.HDR), ([0], "from defect_cpu0.meta"))
            self.assertEqual(rl.resolve_cpus("2,0", trace, self.HDR), ([0, 2], "--cpus"))   # beats .meta
            self.assertEqual(rl.resolve_cpus("all", trace, self.HDR), ([0, 1, 2, 3], "--cpus"))

    def test_bad_cpu_is_fatal(self):
        for spec in ("7", "x", "-1"):
            with self.assertRaises(rl.TraceError):
                rl.resolve_cpus(spec, None, self.HDR)
        self.assertEqual(run_main(handoff_trace(), "--cpus", "9")[0], 2)

    def test_header_line_says_where_the_cpus_came_from(self):
        code, out, _ = run_main(handoff_trace(), "--cpus", "0")
        self.assertIn("autopsy cpus: 0 (--cpus)", out)


def random_trace(rng):
    """A messy but parseable trace: random dispatches, wakes, leaves, interrupts and
    sleeps on 2-4 CPUs, equal timestamps on purpose, and requests whose markers are
    emitted by whoever was just dispatched. Not realistic; meant to stress the
    interval bookkeeping."""
    ncpu = rng.randint(2, 4)
    hdr = HEADER.replace("TRACE_CPU_NUM:: 2", f"TRACE_CPU_NUM:: {ncpu}")
    others = [(400 + i, 1, rng.randint(1, 60)) for i in range(4)]
    worker = (W[0], W[1], rng.choice([10, 30]))
    pool = others + [(C[0], C[1], 30), (S[0], S[1], 30), worker, (K[0], K[1], 255)] + \
           [(1, c + 1, 0) for c in range(ncpu)]
    out, t = [], 1

    def noise():
        nonlocal t
        for _ in range(rng.randint(0, 6)):
            t += rng.randint(0, 20)
            cpu, (pid, tid, prio) = rng.randrange(ncpu), rng.choice(pool)
            state = rng.choice(["THRUNNING", "THRUNNING", "THREADY", "THRECEIVE", "THCONDVAR",
                                "THNANOSLEEP", "THSEM", "THINTR" if pid == 1 else "THREPLY"])
            out.append(th(t, cpu, state, pid, tid, prio))

    def emit(code, who, rid):
        nonlocal t
        noise()
        t += rng.randint(0, 5)
        cpu = rng.randrange(ncpu)
        out.append(th(t, cpu, "THRUNNING", *who))
        t += rng.randint(0, 3)                    # 0: marker at the dispatch's timestamp
        out.append(mark(t, cpu, code, rid, who[2] if code in (101, 102) else 0))

    for rid in range(1, rng.randint(3, 12)):
        if rng.random() < 0.6:                    # a release: the client sleeps, then wakes
            noise()
            out.append(th(t, rng.randrange(ncpu), "THNANOSLEEP", C[0], C[1], 30))
            noise()
            t += 1
            out.append(th(t, rng.randrange(ncpu), "THREADY", C[0], C[1], 30))
        replier = worker if rng.random() < 0.5 else (S[0], S[1], 30)
        for code, who in ((100, (C[0], C[1], 30)), (101, (S[0], S[1], 30)), (102, replier),
                          (103, (C[0], C[1], 30))):
            emit(code, who, rid)
    return hdr + ev(0, 0, "CONTROL", "TIME", "msb:0x00000000 lsb(offset):0x00000000") + "".join(out), ncpu


def interval(r):
    return r.resp if r.release is not None else r.total


def check_sums(tc, res):
    """Both views add up to the interval, and both causes' parts to the lost time."""
    done = [r for r in res.rows if r.autopsy is not None]
    for r in done:
        a = r.autopsy
        for v, c in ((a.split, a.cause_split), (a.own, a.cause)):
            tc.assertEqual(v.total(), interval(r), r.label)
            tc.assertEqual(sum(c.by_cause.values()), c.lost, r.label)
            tc.assertEqual(c.lost + v.buckets["running"], interval(r), r.label)
    return len(done)


class Invariant(unittest.TestCase):
    """Every view's buckets add up exactly to the request's interval."""

    def check(self, res):
        return check_sums(self, res)

    def test_random_traces(self):
        checked = 0
        for seed in range(80):
            text, ncpu = random_trace(random.Random(seed))
            res = rl.analyze(io.StringIO(text), f"<random {seed}>")
            cpus = sorted(random.Random(seed + 1000).sample(range(ncpu), random.randint(1, ncpu)))
            rl.run_autopsy(res, cpus, "test")
            with self.subTest(seed=seed):
                checked += self.check(res)
        self.assertGreater(checked, 200)          # the generator really produced requests

    @unittest.skipUnless(PROBE.exists(), f"{PROBE} missing (gitignored); see CLAUDE.md")
    def test_kill_check_trace(self):
        with open(PROBE, encoding="utf-8", errors="replace") as f:
            res = rl.analyze(f, str(PROBE))
        rl.run_autopsy(res, *rl.resolve_cpus(None, str(PROBE), res.header))
        self.assertEqual(self.check(res), 20)


CAP1 = REPO / "traces" / "2026-11-13-demo"            # capture 1
CAP3 = REPO / "traces" / "2026-11-14-demo-precise"    # capture 3


@functools.lru_cache(maxsize=None)
def capture(path):
    """Analyze a real capture once per test run (~1.5 s each), CPUs from its .meta."""
    with open(path, encoding="utf-8", errors="replace") as f:
        res = rl.analyze(f, str(path))
    rl.run_autopsy(res, *rl.resolve_cpus(None, str(path), res.header))
    return res


class Captures(unittest.TestCase):
    """Expectations on real Pi captures (measured, 2026-11-20). Thresholds sit well
    below the measured values, so they hold the behaviour without being flaky."""

    def load(self, folder, scenario):
        path = folder / f"{scenario}.txt"
        if not path.exists():
            self.skipTest(f"{path} missing (gitignored); rebuild it from {scenario}.kev "
                          f"with traceprinter.exe, see CLAUDE.md")
        res = capture(path)
        self.assertEqual(res.warnings, [])
        self.assertEqual(check_sums(self, res), 200)
        return res

    def test_capture1_fixed_slowest_request_unplanted_case(self):
        # Nobody planted this: the slowest 'fixed' request of capture 1 (0:48, on time)
        # waited ~88 us behind the SD-card driver at 50, which served tracelogger's
        # writes. Own view: higher-priority load. Split view: the three prio-20 hogs
        # on the other cores dominate, so there it is "not migrated" (documented QNX
        # behaviour, see CLAUDE.md).
        res = self.load(CAP1, "fixed")
        r = max((r for r in res.rows if r.autopsy), key=interval)
        a = r.autopsy
        self.assertEqual(r.label, "0:48")
        (pid, tid, prio, label), _ = a.own.culprits.most_common(1)[0]
        self.assertTrue(res.timeline.name((pid, tid)).startswith("devb-sdmmc-bcm2712/"))
        self.assertEqual((prio, label, a.cause.name), (50, "higher", LOAD))
        self.assertEqual(a.cause_split.name, NOTMIG)
        hogs = {res.timeline.name(k[:2]) for k, _ in a.split.culprits.most_common(3)}
        self.assertEqual(hogs, {"rl_demo/rl_hog0", "rl_demo/rl_hog2", "rl_demo/rl_hog3"})

    def test_capture3_pinned_defect_is_rule1_behind_the_hog(self):
        res = self.load(CAP3, "defect_cpu0")
        hog_pid = int(re.search(r"hog: pid (\d+)", (CAP3 / "defect_cpu0.hog.log").read_text())[1])
        late = [r for r in res.rows if r.late]
        self.assertEqual((res.cpus, len(late)), ([0], 175))
        higher = sum(r.autopsy.own.buckets["higher"] for r in late)
        self.assertGreaterEqual(higher / sum(map(interval, late)), 0.8)       # measured 90%
        top = Counter()
        for r in late:
            top.update(r.autopsy.own.culprits)
        (pid, _, prio, label), _ = top.most_common(1)[0]
        self.assertEqual((pid, prio, label), (hog_pid, 20, "higher"))
        rule1 = sum(r.autopsy.cause.rule == ap.RULE1 for r in late)
        self.assertGreaterEqual(rule1, 0.9 * len(late))                        # measured 175/175

    def test_capture3_controls_are_overload_not_inversion(self):
        for scenario in ("control_rr", "control_fifo"):
            with self.subTest(scenario):
                late = [r for r in self.load(CAP3, scenario).rows if r.late]
                self.assertGreater(len(late), 100)                            # measured 126, 148
                names = Counter(r.autopsy.cause.name for r in late)
                self.assertGreaterEqual(names[OVER], 0.9 * len(late))         # measured all
                self.assertEqual(names[INV], 0)                               # the negative control

    def test_capture3_fixed_runs_barely_wait(self):
        for scenario in ("fixed", "fixed_direct"):
            with self.subTest(scenario):
                res = self.load(CAP3, scenario)
                done = [r for r in res.rows if r.autopsy]
                ready = sum(sum(r.autopsy.ready.values()) for r in done) / len(done)
                self.assertLess(ready * 10**6 / res.cps, 50)                  # measured 8.0, 5.2 us
                self.assertFalse(any(r.late for r in done))


if __name__ == "__main__":
    unittest.main()
