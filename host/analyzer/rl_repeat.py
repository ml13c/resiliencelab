#!/usr/bin/env python3
"""rl_repeat.py - repeatability and tracing overhead across repeated demo runs.

Reads a folder written by `sh run_demo.sh repeat N`: for every run <name>.meta
(with trace= and round=), <name>.client.log, and for traced runs <name>.txt
(traceprinter output, converted on Windows from <name>.kev).

Two instruments, kept apart:
  client    rl_demo's own numbers, in EVERY run: send (100 -> 103) and resp
            (scheduled release -> reply) per request, late counts on both.
            Untraced runs have nothing else, so the tracing-overhead comparison
            uses client numbers only, the same instrument on both sides.
  analyzer  rl_analyze on the kernel trace, traced runs only: the release-based
            verdict (release = kernel wake-up), and the autopsy's causes.

Per (scenario, traced/untraced): each metric's median [min-max] across runs.
Per scenario: on - off, the difference of the medians, and whether the on and
off ranges overlap. No significance test is claimed: with 10 runs per side,
the ranges are the honest summary.

Usage:  python rl_repeat.py <folder> [--json PATH | --json -]
Exit:   0 = clean, 1 = warnings (printed to stderr), 2 = fatal (no runs found).
Stdlib only, Python 3.12.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import statistics
import sys
from collections import Counter
from dataclasses import dataclass, field
from fractions import Fraction

import rl_analyze as rl

# "req 0:1     send    6488.8 us  resp    6518.3 us  LATE(send)  LATE(resp)"
REQ_RE = re.compile(r"^req (\d+):(\d+)\s+send\s+(\S+) us\s+resp\s+(\S+) us(.*)$")
DEADLINE_RE = re.compile(r"^deadline (\d+) us: (\d+)/(\d+) late from send, (\d+)/(\d+) late from release")
SKIPPED_RE = re.compile(r"^releases skipped .*: (\d+)$")
FUNCTIONAL_RE = re.compile(r"^functional: (\d+)/(\d+) correct")
RELDELAY_RE = re.compile(r"^release delay us .*: median (\S+)\s+max (\S+)")

# Client metrics, in report order: (key, label). Every run has them.
CLIENT_METRICS = (
    ("late_resp", "late (client, from release)"),
    ("late_send", "late (client, from send)"),
    ("resp_p50", "resp p50 us"),
    ("resp_p99", "resp p99 us"),
    ("resp_max", "resp max us"),
    ("send_p50", "send p50 us"),
    ("send_p99", "send p99 us"),
    ("skipped", "releases skipped"),
    ("release_delay_p50", "release delay p50 us"),
)
# Traced runs only.
TRACED_METRICS = (
    ("late_analyzer", "late (analyzer, kernel release)"),
    ("dominant_share", "dominant cause (most common among late requests), % of lost time"),
    ("rule1", "late requests with rule 1"),
    ("wake_offset_p50", "client resp - analyzer resp, p50 us"),
)
OVERHEAD_METRICS = ("late_resp", "resp_p50", "resp_p99", "send_p50", "send_p99", "skipped",
                    "release_delay_p50")


@dataclass
class ClientLog:
    seqs: list[int] = field(default_factory=list)
    send_us: list[float] = field(default_factory=list)
    resp_us: list[float] = field(default_factory=list)
    late_send: int = 0
    late_resp: int = 0
    wrong: int = 0
    errors: int = 0                      # requests whose MsgSend failed (errno text)
    deadline_us: int | None = None
    skipped: int | None = None
    correct: int | None = None
    count: int | None = None
    release_delay_p50: float | None = None


def parse_client_log(text: str, warn) -> ClientLog:
    """rl_demo client output (the format from 2026-11-20 on: send and resp per request)."""
    c = ClientLog()
    summary = None
    for line in text.splitlines():
        m = REQ_RE.match(line)
        if m:
            c.seqs.append(int(m[2]))
            c.send_us.append(float(m[3]))
            c.resp_us.append(float(m[4]))
            flags = m[5].split()
            c.late_send += "LATE(send)" in flags
            c.late_resp += "LATE(resp)" in flags
            c.wrong += "WRONG" in flags
            c.errors += any(f not in ("LATE(send)", "LATE(resp)", "WRONG") for f in flags)
            continue
        if m := DEADLINE_RE.match(line):
            c.deadline_us = int(m[1])
            summary = (int(m[2]), int(m[4]))
        elif m := SKIPPED_RE.match(line):
            c.skipped = int(m[1])
        elif m := FUNCTIONAL_RE.match(line):
            c.correct, c.count = int(m[1]), int(m[2])
        elif m := RELDELAY_RE.match(line):
            c.release_delay_p50 = float(m[1])
    if not c.send_us:
        warn("no per-request lines with send and resp (client built before 2026-11-20?)")
    if summary is None:
        warn("no 'deadline ... late from send, ... late from release' summary line")
    elif summary != (c.late_send, c.late_resp):
        warn(f"summary says {summary[0]} late from send / {summary[1]} from release, but the "
             f"per-request flags count {c.late_send} / {c.late_resp}")
    if c.count is not None and c.correct != c.count:
        warn(f"functional failure: {c.correct}/{c.count} correct")
    if c.wrong or c.errors:
        warn(f"{c.wrong} wrong replies, {c.errors} failed sends")
    return c


def percentile(values: list[float], p: float) -> float | None:
    """Nearest-rank percentile (p in 0..100): an actual sample, no interpolation."""
    if not values:
        return None
    s = sorted(values)
    return s[max(0, math.ceil(p / 100 * len(s)) - 1)]


def spread(values: list) -> dict | None:
    """min / median / max of the values that exist (None = not measured)."""
    v = [x for x in values if x is not None]
    if not v:
        return None
    return {"min": min(v), "median": statistics.median(v), "max": max(v), "n": len(v)}


def overlap(a: dict | None, b: dict | None) -> bool | None:
    if a is None or b is None:
        return None
    return not (a["max"] < b["min"] or b["max"] < a["min"])


@dataclass
class Run:
    name: str
    scenario: str
    traced: bool
    round: int
    metrics: dict = field(default_factory=dict)
    dominant: str | None = None          # traced: most common cause among late requests
    top_culprit: str | None = None       # traced: e.g. "rl_demo/rl_hog*@20 higher"
    warnings: list[str] = field(default_factory=list)


def read_meta(path: str) -> dict[str, str]:
    with open(path, encoding="utf-8") as f:
        return dict(ln.split("=", 1) for ln in f.read().splitlines()
                    if "=" in ln and not ln.startswith("#"))


def generic(name: str) -> str:
    """'rl_demo/rl_hog3' -> 'rl_demo/rl_hog*': the hog threads are interchangeable.
    Unnamed threads ('pid/tid', all digits) are left alone: the tid is not a suffix."""
    if re.fullmatch(r"\d+/\d+", name):
        return name
    return re.sub(r"(?<=[A-Za-z_])\d+$", "*", name)


def analyze_trace(run: Run, path: str, client: ClientLog) -> None:
    """Analyzer metrics for one traced run (rl_analyze + autopsy, CPUs from its .meta)."""
    with open(path, encoding="utf-8", errors="replace") as f:
        res = rl.analyze(f, path)
    rl.run_autopsy(res, *rl.resolve_cpus(None, path, res.header))
    run.warnings += [f"analyzer: {w}" for w in res.warnings]
    s, a = rl.summarize(res), rl.autopsy_summary(res)
    m = run.metrics
    m["late_analyzer"] = s["late"]
    m["rule1"] = sum(a["rules"].values())
    if a["late"]:
        run.dominant = a["causes"].most_common(1)[0][0]
        # Its share of the late requests' lost time. "mixed" and "service time" are
        # not lost-time causes, so they have no share.
        lost = a["lost"]["own"]
        total = sum(lost.values(), Fraction(0))
        m["dominant_share"] = (round(float(100 * lost[run.dominant] / total), 1)
                               if total and run.dominant in lost else None)
    else:
        run.dominant = "none late"
    if a["top_culprits"]:
        (pid, tid, prio, label), _ = a["top_culprits"][0]
        run.top_culprit = f"{generic(res.timeline.name((pid, tid)))}@{prio} {label}"
    # The two release-based numbers differ by when the release is taken: the
    # client's schedule vs the kernel's wake-up. Matched by request sequence number.
    kernel = {r.rid & 0xFFFFFF: r.resp * 1e6 / res.cps for r in res.rows if r.resp is not None}
    diffs = [cr - kernel[q] for q, cr in zip(client.seqs, client.resp_us) if q in kernel]
    m["wake_offset_p50"] = round(statistics.median(diffs), 1) if diffs else None


def load_run(folder: str, meta_name: str) -> Run | None:
    meta = read_meta(os.path.join(folder, meta_name))
    if "trace" not in meta or "round" not in meta:
        return None                                  # not a repeat run
    name = meta_name[:-len(".meta")]
    run = Run(name, meta.get("scenario", name), meta["trace"] == "on", int(meta["round"]))

    def warn(msg: str) -> None:
        run.warnings.append(msg)

    log = os.path.join(folder, f"{name}.client.log")
    if not os.path.exists(log):
        warn("no client log")
        return run
    with open(log, encoding="utf-8", errors="replace") as f:
        c = parse_client_log(f.read(), warn)
    run.metrics.update({
        "late_resp": c.late_resp, "late_send": c.late_send,
        "resp_p50": percentile(c.resp_us, 50), "resp_p99": percentile(c.resp_us, 99),
        "resp_max": max(c.resp_us, default=None),
        "send_p50": percentile(c.send_us, 50), "send_p99": percentile(c.send_us, 99),
        "skipped": c.skipped, "release_delay_p50": c.release_delay_p50,
    })
    if run.traced:
        txt = os.path.join(folder, f"{name}.txt")
        if not os.path.exists(txt):
            warn(f"traced run has no {name}.txt: convert {name}.kev with traceprinter.exe first")
        else:
            try:
                analyze_trace(run, txt, c)
            except rl.TraceError as e:
                warn(f"analyzer: {e}")
    return run


@dataclass
class Report:
    folder: str
    runs: list[Run]
    groups: dict = field(default_factory=dict)       # (scenario, traced) -> {metric: spread}
    overhead: dict = field(default_factory=dict)     # scenario -> {metric: {...}}
    warnings: list[str] = field(default_factory=list)


def build(folder: str, progress=None) -> Report:
    if not os.path.isdir(folder):
        raise rl.TraceError(f"{folder} is not a folder")
    metas = sorted(f for f in os.listdir(folder) if f.endswith(".meta"))
    runs = []
    for i, meta in enumerate(metas, 1):
        if progress:
            progress(f"[{i}/{len(metas)}] {meta[:-5]}")
        run = load_run(folder, meta)
        if run is not None:
            runs.append(run)
    if not runs:
        raise rl.TraceError(f"no repeat runs in {folder} (no .meta with trace= and round=)")
    rep = Report(folder, runs)
    for r in runs:
        rep.warnings += [f"{r.name}: {w}" for w in r.warnings]
    keys = [k for k, _ in CLIENT_METRICS + TRACED_METRICS]
    for scen in sorted({r.scenario for r in runs}):
        for traced in (True, False):
            sel = [r for r in runs if r.scenario == scen and r.traced == traced]
            if sel:
                rep.groups[(scen, traced)] = {k: spread([r.metrics.get(k) for r in sel]) for k in keys}
        on, off = rep.groups.get((scen, True)), rep.groups.get((scen, False))
        n_on = sum(r.scenario == scen and r.traced for r in runs)
        n_off = sum(r.scenario == scen and not r.traced for r in runs)
        if n_on != n_off:
            rep.warnings.append(f"{scen}: {n_on} traced runs but {n_off} untraced")
        if on and off:
            rep.overhead[scen] = {
                k: {"on": on[k]["median"] if on[k] else None,
                    "off": off[k]["median"] if off[k] else None,
                    "diff": (on[k]["median"] - off[k]["median"]) if on[k] and off[k] else None,
                    "overlap": overlap(on[k], off[k])}
                for k in OVERHEAD_METRICS}
    return rep


def _cell(s: dict | None, digits: int) -> str:
    if s is None:
        return "-"
    f = (lambda x: f"{x:.{digits}f}") if digits else (lambda x: f"{x:g}")
    return f"{f(s['median'])} [{f(s['min'])}-{f(s['max'])}]"


def print_report(rep: Report, out=None) -> None:
    out = out or sys.stdout
    n_scen = len({r.scenario for r in rep.runs})
    rounds = sorted({r.round for r in rep.runs})
    print(f"repeat: {rep.folder}  runs: {len(rep.runs)} ({n_scen} scenarios, rounds "
          f"{rounds[0]}-{rounds[-1]}, traced and untraced)", file=out)
    print("each cell: median [min-max] across runs; latencies in us. late_resp, late_send, resp, "
          "send: the client's own numbers (every run); late_analyzer: kernel trace (traced runs).",
          file=out)
    cols = (("late_resp", 0, 14), ("late_send", 0, 14), ("late_analyzer", 0, 14),
            ("resp_p50", 1, 26), ("resp_p99", 1, 26), ("send_p50", 1, 22), ("skipped", 0, 10))
    print(f"{'scenario':<14}{'trace':<6}{'runs':>5}  " + "".join(f"{k:<{w}}" for k, _, w in cols),
          file=out)
    for (scen, traced), g in rep.groups.items():
        n = sum(r.scenario == scen and r.traced == traced for r in rep.runs)
        print(f"{scen:<14}{'on' if traced else 'off':<6}{n:>5}  "
              + "".join(f"{_cell(g[k], d):<{w}}" for k, d, w in cols), file=out)

    print("\ncauses (traced runs, own-CPU view):", file=out)
    for scen in sorted({r.scenario for r in rep.runs}):
        traced = [r for r in rep.runs if r.scenario == scen and r.traced]
        if not traced:
            continue
        g = rep.groups[(scen, True)]
        dom = ", ".join(f"{k} {n}/{len(traced)}" for k, n in
                        Counter(r.dominant or "?" for r in traced).most_common())
        top = ", ".join(f"{k} {n}/{len(traced)}" for k, n in
                        Counter(r.top_culprit or "-" for r in traced).most_common(2))
        print(f"  {scen:<14}dominant: {dom}; share {_cell(g['dominant_share'], 1)}%; "
              f"rule 1 {_cell(g['rule1'], 0)}; top culprit: {top}; "
              f"client - analyzer resp {_cell(g['wake_offset_p50'], 1)} us", file=out)

    if rep.overhead:
        print("\ntracing overhead: on - off (difference of medians); "
              "'no overlap' = the on and off ranges are disjoint", file=out)
        for scen, o in rep.overhead.items():
            parts = []
            for k in OVERHEAD_METRICS:
                d = o[k]
                if d["diff"] is None:
                    continue
                parts.append(f"{k} {d['diff']:+.1f}" + ("" if d["overlap"] else " (no overlap)"))
            print(f"  {scen:<14}" + ", ".join(parts), file=out)


JSON_SCHEMA = "resiliencelab.repeat/0"


def to_json(rep: Report) -> dict:
    return {
        "schema": JSON_SCHEMA,
        "folder": rep.folder,
        "runs": [{"name": r.name, "scenario": r.scenario, "traced": r.traced, "round": r.round,
                  "metrics": r.metrics, "dominant_cause": r.dominant, "top_culprit": r.top_culprit,
                  "warnings": r.warnings} for r in rep.runs],
        "groups": [{"scenario": s, "traced": t, "metrics": g} for (s, t), g in rep.groups.items()],
        "overhead": rep.overhead,
        "warnings": rep.warnings,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Repeatability and tracing overhead across "
                                             "run_demo.sh repeat runs.")
    ap.add_argument("folder", help="folder written by 'sh run_demo.sh repeat N', .kev converted to .txt")
    ap.add_argument("--json", metavar="PATH", help="also write JSON to PATH; '-' prints JSON instead")
    ap.add_argument("--quiet", action="store_true", help="no progress lines on stderr")
    args = ap.parse_args(argv)
    progress = None if args.quiet else (lambda s: print(s, file=sys.stderr, flush=True))
    try:
        rep = build(args.folder, progress)
    except (OSError, rl.TraceError) as e:
        print(f"rl_repeat: error: {e}", file=sys.stderr)
        return 2
    if args.json == "-":
        json.dump(to_json(rep), sys.stdout, indent=1)
        print()
    else:
        print_report(rep)
        if args.json:
            with open(args.json, "w", encoding="utf-8") as f:
                json.dump(to_json(rep), f, indent=1)
                f.write("\n")
    for w in rep.warnings:
        print(f"warning: {w}", file=sys.stderr)
    return 1 if rep.warnings else 0


if __name__ == "__main__":
    sys.exit(main())
