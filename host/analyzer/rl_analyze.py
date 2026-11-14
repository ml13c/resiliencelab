#!/usr/bin/env python3
"""rl_analyze.py - ResilienceLab analyzer v0.

Reads traceprinter text output from a tracelogger capture (wide mode, -w) and
rebuilds one row per request from its four user markers (ipc_probe, rl_demo):

    code  meaning                 d1 (0 = not reported)
    100   client request start    deadline in us
    101   server received         receiving thread's own priority
    102   server about to reply   replying thread's own priority
    103   client got reply        1 = reply correct, 2 = wrong
    d0 = request id; rl_demo uses client index << 24 | sequence number.

USREVENT lines carry a CPU number but no pid/tid, so each marker is attributed
to whichever thread the kernel last dispatched on that CPU (see running[cpu]
in analyze()). A request is keyed by (client thread, request id).

Two latencies per request:
  send = marker 100 -> 103: from when the client actually sent.
  resp = release -> 103: from when the request was due. The release is the
         moment the client's sleep ended (THNANOSLEEP -> READY in the kernel
         trace). The late/on-time verdict uses resp, as real-time deadlines
         count from the release. resp - send = wait, the time the client was
         ready but not yet sending (e.g. behind equal-priority load).
         Requests with no sleep before them (the first one) are judged on send.

Usage:  python rl_analyze.py <traceprinter.txt>
Exit:   0 = clean, 1 = warnings (printed to stderr), 2 = fatal (bad input).
        A request the capture ended before it finished gets status "cut off" and
        a note on stderr; that alone is not a warning.
Stdlib only, Python 3.12.
"""
from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable, Iterator, NamedTuple

# Marker codes, mirroring the enum in target/ipc_probe/ipc_probe.cpp.
REQ_START, SRV_GOT, SRV_REPLY, REQ_END = 100, 101, 102, 103
MARKER_CODES = (REQ_START, SRV_GOT, SRV_REPLY, REQ_END)

HEADER_END = "-- KERNEL EVENTS --"
# "  TRACE_CYCLES_PER_SEC:: 54000000"
HEADER_RE = re.compile(r"^\s*(\w+)::\s*(.*?)\s*$")
# Every event starts with a line like
#   t:0x3888459f2d CPU:00 USREVENT        :EVENT:100         , d0:0x00000001 d1:0x00000000
# Indented continuation lines (info->pid:..., sched_priority:...) and blank
# lines don't match, so v0 skips them.
EVENT_RE = re.compile(r"^t:0x([0-9a-fA-F]+) CPU:(\d+) (\S+)\s*:(\S+)\s*(.*)$")
# THREAD events: "pid:13058101 tid:1 priority:30 policy:2". Priority is only
# present in wide mode, and THCREATE has none at all.
THREAD_RE = re.compile(r"pid:(\d+) tid:(\d+)(?: priority:(\d+))?")
USR_CODE_RE = re.compile(r"^EVENT:(\d+)$")
USR_DATA_RE = re.compile(r"d0:0x([0-9a-fA-F]+) d1:0x([0-9a-fA-F]+)")
# "CONTROL :TIME  msb:0x00000038 lsb(offset):0x869c9345"
TIME_RE = re.compile(r"msb:0x([0-9a-fA-F]+) lsb\(offset\):0x([0-9a-fA-F]+)")

LSB_MASK = 0xFFFF_FFFF
WRAP = 1 << 32
HALF_WRAP = 1 << 31   # 2^31 ticks = 39.8 s at 54 MHz


class TraceError(Exception):
    """Input we cannot analyze at all (exit code 2)."""


class Event(NamedTuple):
    t: int        # raw clock ticks (traceprinter already prints the full 64-bit value)
    cpu: int
    cls: str      # THREAD, USREVENT, KER_CALL, ...
    name: str     # THRUNNING, EVENT:101, MSG_SENDV/11, ...
    rest: str
    lineno: int


class Thread(NamedTuple):
    pid: int
    tid: int
    prio: int | None   # priority at the moment it was dispatched

    def label(self) -> str:
        return f"{self.pid}/{self.tid}@{'?' if self.prio is None else self.prio}"


class Marker(NamedTuple):
    code: int
    rid: int                # request id (d0)
    d1: int                 # meaning depends on the code; see the module docstring
    t: int
    cpu: int
    thread: Thread | None   # emitter from running[cpu]; None = unknown
    lineno: int
    woke: int | None = None  # when the emitter's last sleep ended, if after its previous marker


def req_label(rid: int) -> str:
    """'index:seq', the request id as rl_demo builds it (ipc_probe ids show as 0:n)."""
    return f"{rid >> 24}:{rid & 0xFFFFFF}"


ThreadKey = tuple[int, int]   # (pid, tid)


@dataclass
class Row:
    """One request: the first marker seen for each code."""
    rid: int
    m: dict[int, Marker]
    client: ThreadKey | None = None
    # ok | cut off (capture ended first) | incomplete (markers lost)
    # | wrong reply (functional failure) | check (other warning)
    status: str = "ok"
    late: bool | None = None       # None: no deadline, or not finished
    judged_from: str | None = None  # "release", or "send" when no release was found

    @property
    def label(self) -> str:
        return req_label(self.rid)

    def ticks(self, a: int, b: int) -> int | None:
        if a in self.m and b in self.m:
            return self.m[b].t - self.m[a].t
        return None

    @property
    def recv(self) -> int | None:   # client start -> server has the message
        return self.ticks(REQ_START, SRV_GOT)

    @property
    def work(self) -> int | None:   # server handler time
        return self.ticks(SRV_GOT, SRV_REPLY)

    @property
    def reply(self) -> int | None:  # server replies -> client running again
        return self.ticks(SRV_REPLY, REQ_END)

    @property
    def total(self) -> int | None:  # "send" latency: client sent -> got reply
        return self.ticks(REQ_START, REQ_END)

    @property
    def release(self) -> int | None:  # client's sleep ended (kernel), before marker 100
        return self.m[REQ_START].woke if REQ_START in self.m else None

    @property
    def wait(self) -> int | None:   # release -> sent: ready but not yet sending
        r = self.release
        return None if r is None else self.m[REQ_START].t - r

    @property
    def resp(self) -> int | None:   # release -> got reply: what the deadline is about
        r = self.release
        return None if r is None or REQ_END not in self.m else self.m[REQ_END].t - r

    @property
    def deadline_us(self) -> int | None:
        return (self.m[REQ_START].d1 or None) if REQ_START in self.m else None

    def thread(self, code: int) -> Thread | None:
        return self.m[code].thread if code in self.m else None


@dataclass
class Result:
    source: str
    header: dict[str, str]
    cps: int                      # TRACE_CYCLES_PER_SEC
    n_events: int = 0
    n_markers: int = 0
    n_wraps: int = 0              # 32-bit wraps inferred between CONTROL TIME events
    t_end: int | None = None      # timestamp of the last event: where the capture ends
    rows: list[Row] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)   # make the exit code 1
    notes: list[str] = field(default_factory=list)      # information only


@dataclass
class _Group:
    """Markers of one request, before the checks turn them into a Row."""
    rid: int
    client: ThreadKey | None
    got: dict[int, list[Marker]] = field(default_factory=dict)
    flagged: bool = False          # a grouping warning was raised for it

    def add(self, mk: Marker) -> None:
        self.got.setdefault(mk.code, []).append(mk)

    def first_t(self) -> int:
        return min(mk.t for lst in self.got.values() for mk in lst)


@dataclass
class _Ctx:
    """Whole-trace facts the per-request checks need."""
    res: Result
    by_thread: dict[ThreadKey, list[Marker]] = field(default_factory=dict)  # markers per emitter, time order
    died: dict[ThreadKey, tuple[int, int]] = field(default_factory=dict)    # (t, lineno) of THDEAD/THDESTROY

    def warn(self, g: _Group, msg: str) -> None:
        self.res.warnings.append(f"req {req_label(g.rid)}: {msg}")
        g.flagged = True


def parse_header(numbered: Iterator[tuple[int, str]]) -> dict[str, str]:
    """Consume (lineno, line) pairs up to and including ' -- KERNEL EVENTS -- '."""
    header: dict[str, str] = {}
    for _, line in numbered:
        if HEADER_END in line:
            return header
        m = HEADER_RE.match(line)
        if m:
            header[m[1]] = m[2]
    raise TraceError(f"no '{HEADER_END}' line: is this traceprinter output?")


def iter_events(numbered: Iterable[tuple[int, str]]) -> Iterator[Event]:
    for lineno, line in numbered:
        m = EVENT_RE.match(line)
        if m:
            yield Event(int(m[1], 16), int(m[2]), m[3], m[4], m[5], lineno)


class Clock:
    """Rebuilds full 64-bit tick counts from traceprinter timestamps.

    Each trace event stores only the low 32 bits of the 54 MHz counter, which
    wraps every 79.5 s. The kernel also logs CONTROL TIME events (one at the
    start of every trace buffer: every <= 28 ms in the kill-check trace) that
    carry the high 32 bits ("msb"). The Pi's traceprinter combines them and
    prints all 64 bits; the host traceprinter.exe prints only the low 32.

    Rules, applied to every event in file order:
    1. t already above 32 bits -> it is a full value; use it as-is.
    2. CONTROL TIME -> authoritative: full = msb << 32 | lsb. If that differs
       from what rule 3 predicted, warn (and trust the kernel).
    3. Otherwise (32-bit t) -> wrap detection: pick the value with these low
       32 bits that lies nearest the previous full timestamp. Moving forward
       across 0xFFFFFFFF -> 0 increments the msb. This covers events between
       a wrap and the next TIME event. It only fails if consecutive events in
       the file are more than 2^31 ticks (39.8 s) apart.
    The reference is global, not per CPU: all cores read the same counter and
    traceprinter merges the CPUs into one time-ordered stream.
    """

    def __init__(self, warn):
        self.ref: int | None = None   # previous full timestamp
        self.warn = warn
        self.n_wraps = 0              # wraps found by rule 3 (not told by a TIME event)
        self._max_msb = 0
        self._warned_no_msb = False

    def _nearest(self, lsb: int) -> int:
        cand = (self.ref & ~LSB_MASK) | lsb
        if cand - self.ref > HALF_WRAP:      # just before a wrap the ref already passed
            cand -= WRAP
        elif self.ref - cand > HALF_WRAP:    # the low 32 bits wrapped: msb + 1
            cand += WRAP
        return cand

    def full(self, ev: Event) -> int:
        inferred = False
        if ev.t > LSB_MASK:                  # rule 1
            full = ev.t
        elif self.ref is None:               # very first event, msb not known yet
            full = ev.t
        else:                                # rule 3
            full = self._nearest(ev.t)
            inferred = True

        time_m = TIME_RE.search(ev.rest) if (ev.cls, ev.name) == ("CONTROL", "TIME") else None
        if time_m:                           # rule 2
            kernel = (int(time_m[1], 16) << 32) | int(time_m[2], 16)
            if self.ref is not None and kernel != full:
                self.warn(f"line {ev.lineno}: CONTROL TIME says 0x{kernel:x}, timestamps "
                          f"rebuilt so far say 0x{full:x}; using the kernel's value")
            full, inferred = kernel, False
        elif self.ref is None and ev.t <= LSB_MASK and not self._warned_no_msb:
            self._warned_no_msb = True
            self.warn(f"line {ev.lineno}: 32-bit timestamp before any CONTROL TIME; msb assumed 0")

        msb = full >> 32
        if inferred and msb > self._max_msb:
            self.n_wraps += msb - self._max_msb
        self._max_msb = max(self._max_msb, msb)
        self.ref = full
        return full


def analyze(lines: Iterable[str], source: str = "<input>") -> Result:
    # One shared numbered iterator: the header parser stops partway through the
    # file and the event loop continues from there, so line numbers stay true.
    numbered = enumerate(lines, 1)
    header = parse_header(numbered)
    try:
        cps = int(header["TRACE_CYCLES_PER_SEC"])
    except (KeyError, ValueError):
        raise TraceError("header has no usable TRACE_CYCLES_PER_SEC") from None
    if cps <= 0:
        raise TraceError(f"TRACE_CYCLES_PER_SEC is {cps}")
    res = Result(source, header, cps)
    warn = res.warnings.append
    ctx = _Ctx(res)

    # running[cpu] = the thread the kernel last dispatched on that CPU (or None).
    # A CPU runs one thread at a time, and TraceEvent() is a kernel call made
    # by the running thread, so running[cpu] at a USREVENT names its emitter.
    running: dict[int, Thread | None] = {}
    last_t: dict[int, int] = {}
    markers: list[Marker] = []
    unknown_codes: Counter[int] = Counter()
    no_prio = 0
    # Release tracking: a thread's last THREAD state, when its last sleep ended,
    # and the time of its last marker (so a wake counts only for the next request).
    state: dict[ThreadKey, str] = {}
    woke: dict[ThreadKey, int] = {}
    last_mark: dict[ThreadKey, int] = {}

    clock = Clock(warn)
    for ev in iter_events(numbered):
        ev = ev._replace(t=clock.full(ev))   # from here on, t is a full 64-bit tick count
        res.n_events += 1
        res.t_end = ev.t if res.t_end is None else max(res.t_end, ev.t)
        # running[cpu] is only right if each CPU's events arrive in time order.
        if ev.t < last_t.get(ev.cpu, ev.t):
            warn(f"line {ev.lineno}: CPU {ev.cpu} timestamp went backwards")
        last_t[ev.cpu] = ev.t

        if ev.cls == "THREAD":
            m = THREAD_RE.search(ev.rest)
            if not m:
                continue
            th = Thread(int(m[1]), int(m[2]), int(m[3]) if m[3] else None)
            key = (th.pid, th.tid)
            # A sleep ends when the kernel makes the thread READY (timer fired),
            # or RUNNING directly. This can be logged on any CPU.
            if state.get(key) == "THNANOSLEEP" and ev.name in ("THREADY", "THRUNNING"):
                woke[key] = ev.t
            state[key] = ev.name
            if ev.name == "THRUNNING":
                # The kernel dispatched th onto this CPU.
                if th.prio is None:
                    no_prio += 1
                running[ev.cpu] = th
            else:
                # Any other state (THREADY, THREPLY, THRECEIVE, ...) logged on this CPU
                # for the thread we think is running means it has left the CPU. Until
                # the next THRUNNING we don't know who runs here.
                # The same states for OTHER threads must not touch running[cpu]:
                # "CPU:02 THREADY pid:X" means CPU 2 woke X, not that X runs on CPU 2.
                cur = running.get(ev.cpu)
                if cur is not None and (cur.pid, cur.tid) == (th.pid, th.tid):
                    running[ev.cpu] = None
                if ev.name in ("THDEAD", "THDESTROY"):   # used to tell "killed" from "cut off"
                    ctx.died.setdefault((th.pid, th.tid), (ev.t, ev.lineno))

        elif ev.cls == "USREVENT":
            lineno = ev.lineno
            cm, dm = USR_CODE_RE.match(ev.name), USR_DATA_RE.search(ev.rest)
            if not (cm and dm):
                warn(f"line {lineno}: unparseable USREVENT: {ev.name} {ev.rest}")
                continue
            code = int(cm[1])
            if code not in MARKER_CODES:
                unknown_codes[code] += 1   # other apps may emit their own codes
                continue
            emitter = running.get(ev.cpu)
            wake = None
            if emitter is not None:
                key = (emitter.pid, emitter.tid)
                w = woke.get(key)
                if w is not None and w > last_mark.get(key, -1):
                    wake = w
                last_mark[key] = ev.t
            mk = Marker(code, int(dm[1], 16), int(dm[2], 16), ev.t, ev.cpu, emitter, lineno, wake)
            res.n_markers += 1
            if emitter is None:
                warn(f"req {req_label(mk.rid)}: marker {code} (line {lineno}) on CPU {ev.cpu} has "
                     f"unknown emitter (no thread known to be running there)")
            else:
                ctx.by_thread.setdefault((emitter.pid, emitter.tid), []).append(mk)
            markers.append(mk)

    res.n_wraps = clock.n_wraps
    # An empty table with exit 0 would look like "all good"; say why it is empty.
    if res.n_events == 0:
        warn("no trace events recognised: is this traceprinter output with lines like "
             "'t:0x<ticks> CPU:<n> <CLASS> :<EVENT> ...'?")
    elif res.n_markers == 0:
        warn("no ipc_probe markers (user events 100-103) found: "
             "was the probe running during the capture?")
    if no_prio:
        warn(f"{no_prio} THRUNNING events without priority: was the trace captured with -w?")
    if unknown_codes:
        codes = ", ".join(f"{c} x{n}" for c, n in sorted(unknown_codes.items()))
        warn(f"ignored user events with non-probe codes: {codes}")

    for g in sorted(_group(markers, ctx), key=_Group.first_t):
        res.rows.append(_check_request(g, ctx))
    return res


def _group(markers: list[Marker], ctx: _Ctx) -> list[_Group]:
    """Assign markers (in time order) to requests keyed by (client thread, d0).

    Client markers carry the key directly: their emitter is the client thread.
    Server markers (101, 102) only carry d0, so they attach to the request with
    that d0 that is in flight, i.e. its 100 has been seen and its 103 not yet.
    rl_demo makes d0 unique per run (client index in the top 8 bits), so a
    second in-flight request with the same d0 means a collision: warned, never
    silently merged.
    """
    groups: list[_Group] = []
    inflight: dict[int, list[_Group]] = {}    # d0 -> requests between 100 and 103
    ended: dict[tuple, _Group] = {}           # (client, d0) -> last finished request
    pending: dict[int, list[Marker]] = {}     # server markers with no request in flight

    def who(mk: Marker) -> ThreadKey | None:
        return (mk.thread.pid, mk.thread.tid) if mk.thread else None

    def new(rid: int, client: ThreadKey | None) -> _Group:
        g = _Group(rid, client)
        groups.append(g)
        return g

    for mk in markers:
        c, live = who(mk), inflight.setdefault(mk.rid, [])
        if mk.code == REQ_START:
            same = [g for g in live if g.client == c]
            if same:                                    # a second 100 for a live request
                same[0].add(mk)
                continue
            g = new(mk.rid, c)
            g.add(mk)
            for other in live:
                for x in (g, other):
                    ctx.warn(x, f"request id collision: clients {_tk(g.client)} and "
                                f"{_tk(other.client)} both have it in flight")
            live.append(g)
        elif mk.code in (SRV_GOT, SRV_REPLY):
            if not live:
                pending.setdefault(mk.rid, []).append(mk)
                continue
            if len(live) > 1:
                ctx.warn(live[0], f"marker {mk.code} (line {mk.lineno}) matches {len(live)} "
                                  f"requests in flight; attached to the earliest")
            live[0].add(mk)
        else:                                           # REQ_END
            same = [g for g in live if g.client == c]
            if same:
                g = same[0]
            elif len(live) == 1 and (c is None or live[0].client is None):
                g = live[0]
            elif not live and (c, mk.rid) in ended:     # a second 103: a duplicate
                ended[(c, mk.rid)].add(mk)
                continue
            else:                                       # no 100 seen for it
                g = new(mk.rid, c)
                for p in pending.pop(mk.rid, []):
                    g.add(p)
            g.add(mk)
            if g in live:
                live.remove(g)
            ended[(g.client, mk.rid)] = g
    for rid, lst in pending.items():                    # server markers that never matched
        g = new(rid, None)
        for p in lst:
            g.add(p)
    return groups


def _tk(k: ThreadKey | None) -> str:
    return "?" if k is None else f"{k[0]}/{k[1]}"


def _why_not_cut_off(row: Row, ctx: _Ctx) -> str | None:
    """None if the capture ending explains the missing markers, else the reason it doesn't.

    A request counts as cut off at the trace end only when all of these hold:
    - it has its start (100) and only its LAST markers are missing (e.g. 100 101,
      no 102 103), as when the capture stops while the request is in flight;
    - its client thread starts no later request. MsgSend blocks until the reply,
      so a later request from the same thread proves this one finished inside
      the capture: its missing markers were lost, not cut off;
    - its client thread did not die (slay, crash) after starting it.
    """
    present = [c for c in MARKER_CODES if c in row.m]
    if REQ_START not in row.m:
        return "no start marker; the capture may have begun mid-request"
    if present != list(MARKER_CODES[:len(present)]):
        return "markers missing before later ones"
    client = row.thread(REQ_START)
    if client is None:
        return "client thread unknown"
    key, t0 = (client.pid, client.tid), row.m[REQ_START].t
    later = next((mk for mk in ctx.by_thread.get(key, []) if mk.t > t0 and mk.rid != row.rid), None)
    if later:
        return (f"client {client.label()} started request {req_label(later.rid)} later "
                f"(line {later.lineno})")
    death = ctx.died.get(key)
    if death and death[0] > t0:
        return f"client {client.label()} died at line {death[1]}"
    return None


def _check_request(g: _Group, ctx: _Ctx) -> Row:
    def warn(msg: str) -> None:
        ctx.warn(g, msg)

    for code, lst in g.got.items():
        if len(lst) > 1:
            lines = ", ".join(str(mk.lineno) for mk in lst)
            warn(f"marker {code} appears {len(lst)} times (lines {lines}); using the first")
    row = Row(g.rid, {code: lst[0] for code, lst in g.got.items()}, client=g.client)
    if any(mk.thread is None for mk in row.m.values()):
        g.flagged = True                    # its "unknown emitter" warning is already out

    missing = [c for c in MARKER_CODES if c not in row.m]
    if missing:
        names = ", ".join(map(str, missing))
        why_not = _why_not_cut_off(row, ctx)
        if why_not is None:
            row.status = "cut off"
            last = max(row.m.values(), key=lambda mk: mk.t)
            ctx.res.notes.append(
                f"req {row.label}: cut off at trace end (missing {names}); the capture ended "
                f"{fmt_us(ctx.res.t_end - last.t, ctx.res.cps)} us after marker {last.code}")
        else:
            warn(f"missing marker(s) {names} ({why_not})")

    present = [c for c in MARKER_CODES if c in row.m]
    order = sorted(present, key=lambda c: (row.m[c].t, c))
    if order != present:
        warn(f"markers out of order in time: {' '.join(map(str, order))}")

    tc, te = row.thread(REQ_START), row.thread(REQ_END)
    if tc and te and (tc.pid, tc.tid) != (te.pid, te.tid):
        warn(f"client thread differs: 100 from {tc.label()}, 103 from {te.label()}")
    # 101 and 102 from different threads of the SAME process is a handoff (the
    # receive thread passed the request to a worker): expected, shown in the
    # replier column. A different process would mean the markers are mixed up.
    ts, tr = row.thread(SRV_GOT), row.thread(SRV_REPLY)
    if ts and tr and ts.pid != tr.pid:
        warn(f"server process differs: 101 from {ts.label()}, 102 from {tr.label()}")

    # Priority cross-checks: the kernel's dispatch priority vs the priority the
    # thread read for itself (d1). Inherited priority shows up in both.
    for code, who in ((SRV_GOT, "receiving"), (SRV_REPLY, "replying")):
        th, mk = row.thread(code), row.m.get(code)
        if th and mk and mk.d1 and th.prio is not None and th.prio != mk.d1:
            warn(f"{who} thread self-reported priority {mk.d1} but kernel dispatched it at {th.prio}")

    wrong = REQ_END in row.m and row.m[REQ_END].d1 == 2
    if wrong:
        warn("wrong reply (marker 103 d1 = 2): a functional failure")

    # Deadline verdict: from the release when the trace shows one, else from send.
    if row.deadline_us is not None and REQ_END in row.m:
        lat, row.judged_from = (row.resp, "release") if row.resp is not None else (row.total, "send")
        row.late = lat * 1e6 / ctx.res.cps > row.deadline_us

    if wrong:
        row.status = "wrong reply"
    elif row.status != "cut off" and g.flagged:
        row.status = "incomplete" if missing else "check"
    return row


def fmt_us(ticks: int | None, cps: int) -> str:
    """Ticks -> microseconds, 0.1 us resolution. Conversion happens only here."""
    return "-" if ticks is None else f"{ticks * 1e6 / cps:.1f}"


def print_table(res: Result, out=None) -> None:
    out = out or sys.stdout   # looked up at call time, so redirection works
    print(f"trace: {res.source}  cycles/sec: {res.cps}  "
          f"cpus: {res.header.get('TRACE_CPU_NUM', '?')}  events: {res.n_events}  "
          f"markers: {res.n_markers}  requests: {len(res.rows)}"
          + (f"  32-bit wraps rebuilt: {res.n_wraps}" if res.n_wraps else ""), file=out)
    # wait = release -> send; send = 100 -> 103; resp = release -> 103 (the verdict's basis).
    cols = f"{'req':<8}{'client':<16}{'server':<16}{'replier':<10}" \
           f"{'wait_us':>9}{'recv_us':>9}{'work_us':>9}{'reply_us':>9}" \
           f"{'send_us':>9}{'resp_us':>9}{'ddl_us':>8}  {'late':<6}status"
    print(cols, file=out)

    def who(th: Thread | None) -> str:
        return th.label() if th else "?"

    def replier(r: Row) -> str:
        s, p = r.thread(SRV_GOT), r.thread(SRV_REPLY)
        if p is None:
            return "-" if SRV_REPLY not in r.m else "?"
        if s and (s.pid, s.tid) == (p.pid, p.tid):
            return "="                              # same thread received and replied
        if s and s.pid == p.pid:
            return f"/{p.tid}@{'?' if p.prio is None else p.prio}"   # handoff inside the server
        return p.label()

    for r in res.rows:
        cl = r.thread(REQ_START) or r.thread(REQ_END)
        sv = r.thread(SRV_GOT) or r.thread(SRV_REPLY)
        ddl = str(r.deadline_us) if r.deadline_us else "-"
        late = "-" if r.late is None else ("LATE" if r.late else "ok")
        if r.late is not None and r.judged_from == "send":
            late += "*"
        print(f"{r.label:<8}{who(cl):<16}{who(sv):<16}{replier(r):<10}"
              f"{fmt_us(r.wait, res.cps):>9}{fmt_us(r.recv, res.cps):>9}"
              f"{fmt_us(r.work, res.cps):>9}{fmt_us(r.reply, res.cps):>9}"
              f"{fmt_us(r.total, res.cps):>9}{fmt_us(r.resp, res.cps):>9}{ddl:>8}  "
              f"{late:<6}{r.status}", file=out)

    judged = [r for r in res.rows if r.late is not None]
    if judged:
        n_late = sum(r.late for r in judged)
        n_send = sum(r.judged_from == "send" for r in judged)
        print(f"deadline: {n_late}/{len(judged)} late, judged on resp (release -> reply)"
              + (f"; {n_send} marked * judged on send (no release in the trace)" if n_send else ""),
              file=out)
    flags = [r.m[REQ_END].d1 for r in res.rows if REQ_END in r.m and r.m[REQ_END].d1]
    if flags:
        print(f"replies: {flags.count(1)} correct, {flags.count(2)} wrong", file=out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="ResilienceLab analyzer v0: per-request table "
                                             "from traceprinter output.")
    ap.add_argument("trace", help="traceprinter text output (from a tracelogger -w capture)")
    args = ap.parse_args(argv)
    try:
        with open(args.trace, encoding="utf-8", errors="replace") as f:
            res = analyze(f, args.trace)
    except (OSError, TraceError) as e:
        print(f"rl_analyze: error: {e}", file=sys.stderr)
        return 2
    print_table(res)
    for n in res.notes:
        print(f"note: {n}", file=sys.stderr)
    for w in res.warnings:
        print(f"warning: {w}", file=sys.stderr)
    return 1 if res.warnings else 0


if __name__ == "__main__":
    sys.exit(main())
