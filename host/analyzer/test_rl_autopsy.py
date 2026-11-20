"""Tests for rl_autopsy.py (where a request's time went).

Run:  python -m unittest discover -s host\\analyzer -v

The hand-built trace below is synthetic (not a measurement). Every bucket is
worked out by hand in the comments, so the expected values are a spec, not a
copy of the output. The invariant tests check the one property everything else
relies on: each view's buckets add up EXACTLY to the request's interval.
"""
import io
import os
import random
import sys
import tempfile
import unittest
from fractions import Fraction
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rl_analyze as rl  # noqa: E402
import rl_autopsy as ap  # noqa: E402
from test_rl_analyze import HEADER, START, PROBE, ev, mark, th, run_main  # noqa: E402

C, S, W, H, K = (100, 1), (200, 1), (200, 2), (300, 1), (1, 6)   # client, server, worker, hog, ISR


def handoff_trace(hog_prio=20):
    """One request with a handoff, all chain activity on CPU 0 (1 tick = 1 us).

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
    e = [
        th(1, 1, "THRUNNING", 1, 2, 0),            # idle_cpu_1 on CPU 1
        th(2, 1, "THINTR", *K, 255),               # K waits for interrupts: an ISR thread
        th(5, 0, "THRECEIVE", *S, 10), th(6, 0, "THCONDVAR", *W, 10),
        th(10, 0, "THRUNNING", *C, 30), mark(20, 0, 100, 1), th(21, 0, "THREPLY", *C, 30),
        th(22, 0, "THRUNNING", *S, 30), mark(30, 0, 101, 1, 30),
        th(31, 0, "THREADY", *W, 10), th(32, 0, "THRECEIVE", *S, 30),
        th(33, 0, "THRUNNING", *H, hog_prio),
        th(100, 1, "THRUNNING", *K, 255), th(150, 1, "THINTR", *K, 255), th(151, 1, "THRUNNING", 1, 2, 0),
        th(433, 0, "THNANOSLEEP", *H, hog_prio), th(434, 0, "THRUNNING", *W, 10),
        mark(934, 0, 102, 1, 10),
        th(935, 0, "THREADY", *C, 30), th(936, 0, "THCONDVAR", *W, 10), th(937, 0, "THRUNNING", *C, 30),
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
        self.assertEqual(a.own.buckets, a.split.buckets)     # one CPU: the two views agree

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
        self.assertEqual(dict(a.own.buckets), {**NOT_READY, "higher": 401, "switching": 3, "lower": 1})
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


class Invariant(unittest.TestCase):
    """Every view's buckets add up exactly to the request's interval."""

    def check(self, res):
        done = [r for r in res.rows if r.autopsy is not None]
        for r in done:
            self.assertEqual(r.autopsy.split.total(), interval(r), r.label)
            self.assertEqual(r.autopsy.own.total(), interval(r), r.label)
        return len(done)

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


if __name__ == "__main__":
    unittest.main()
