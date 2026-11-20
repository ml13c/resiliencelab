"""rl_autopsy.py - where a request's time went, from the kernel's point of view.

For each request, the interval it is judged on (release -> reply, or send ->
reply when there is no release) is split into phases. Each phase has a
*holder*, the thread the request is waiting on at that moment:

    release -> 100   client          (marker 100's emitter)
    100 -> 101       server thread   (101's emitter)
    101 -> 102       replier         (102's emitter: the worker after a handoff)
    102 -> 103       client

At every instant of a phase, the holder's own kernel state picks the bucket:

    RUNNING -> "running"
    READY   -> charged to whatever ran instead, in two views (below)
    other   -> "blocked:<STATE>", e.g. "blocked:THCONDVAR"

Two views of READY time, both reported:

  split   The instant is divided equally across the CPUs the holder may run on
          (all cores, or the scenario's --cpu core), and each CPU's share is
          charged to the thread running there. This answers "who held the
          cores this thread was allowed to use".
  own     The whole instant is charged to the thread running on the CPU where
          the kernel made the holder READY (the CPU of its THREADY event).
          QNX 8.0 doesn't migrate a woken thread by preempting lower-priority
          work on another CPU. A thread made ready on CPU A displaces only a
          lower-priority thread on CPU A; other CPUs pick it up at their next
          scheduling decision (Programmer's Guide, "Thread displacement on
          multicore systems"). Measured: 73-92% of READY intervals ended on the
          CPU where they began. So this view answers "who held the CPU it
          was actually queued on".

Labels for a CPU's share, first match wins: "idle core", "switching" (no
thread known on that CPU between a leave and the next THRUNNING), "interrupt"
(a thread seen in THINTR, i.e. an interrupt-service thread), then "higher",
"equal" or "lower" priority vs the holder's current priority, else "unknown".
A "lower" share in the split view means the holder waited while a lower-
priority thread ran on another allowed CPU. That isn't a scheduler fault; see
above. The cause for it is named "not migrated".

In the own view, a "lower" share is relabelled "wake-up switch" when the thread
running there is the one that was already running on that CPU when the THREADY
was logged, and it hasn't left since (a priority change in between doesn't
count as leaving): usually the waker finishing its kernel call before the
switch (e.g. the replier after MsgReply readied the client, measured ~0.5 us),
or a thread a timer interrupt interrupted. That is wake-up latency on the
holder's own CPU, not missing migration.

Every instant lands in exactly one bucket, or is split into n equal shares, so
each view's buckets add up exactly to the interval. Shares are
fractions.Fraction of clock ticks, so the sum is exact, not approximately right.

Stdlib only. Does not import rl_analyze (no import cycle); rl_analyze feeds
the Timeline while it parses.
"""
from __future__ import annotations

import bisect
from collections import Counter
from dataclasses import dataclass, field
from fractions import Fraction

Key = tuple[int, int]                    # (pid, tid)
Running = tuple[int, int, "int | None"]  # (pid, tid, prio) dispatched on a CPU
State = tuple[str, "int | None", int]    # (state, prio, cpu the event was logged on)

RUNNING, READY = "THRUNNING", "THREADY"
IDLE_PID, IDLE_PRIO = 1, 0               # procnto's idle_cpu_N threads
PRIORITY_LABELS = ("higher", "equal", "lower")
WAKEUP = "wake-up switch"                # own view only: a bucket, culprit label and cause
CULPRIT_LABELS = PRIORITY_LABELS + (WAKEUP,)   # shares charged to a named thread


class Timeline:
    """What ran on each CPU, and each thread's state, over the whole trace.

    running(cpu) is the thread the kernel last dispatched on that CPU
    (THRUNNING), or None once that thread is logged in another state ON THAT
    CPU. Other threads' events don't touch it: "CPU:02 THREADY pid:X" means
    CPU 2 woke X, not that X runs on CPU 2. rl_analyze uses running(cpu) at
    each user marker to name the marker's emitter.
    """

    def __init__(self) -> None:
        self._run_t: dict[int, list[int]] = {}             # cpu -> change times
        self._run_v: dict[int, list[Running | None]] = {}  # cpu -> value from then on
        self._now: dict[int, Running | None] = {}
        self._st_t: dict[Key, list[int]] = {}              # thread -> state change times
        self._st_v: dict[Key, list[State]] = {}
        self.isr: set[Key] = set()                         # interrupt-service threads
        self.proc_names: dict[int, str] = {}
        self.thread_names: dict[Key, str] = {}

    def record_thread(self, t: int, cpu: int, state: str, pid: int, tid: int,
                      prio: int | None) -> None:
        key = (pid, tid)
        self._st_t.setdefault(key, []).append(t)
        self._st_v.setdefault(key, []).append((state, prio, cpu))
        if state == "THINTR":
            self.isr.add(key)
        cur = self._now.get(cpu)
        if state == RUNNING:
            self._set(t, cpu, (pid, tid, prio))
        elif cur is not None and cur[:2] == key:
            self._set(t, cpu, None)          # it left this CPU; who runs next is unknown

    def _set(self, t: int, cpu: int, value: Running | None) -> None:
        self._now[cpu] = value
        self._run_t.setdefault(cpu, []).append(t)
        self._run_v.setdefault(cpu, []).append(value)

    def running(self, cpu: int) -> Running | None:
        """Who runs on cpu right now (while parsing)."""
        return self._now.get(cpu)

    def record_name(self, kind: str, fields: dict[str, str]) -> None:
        """PROCCREATE_NAME (pid, name) or PROCTHREAD_NAME (pid, tid, name)."""
        try:
            if kind == "PROCCREATE_NAME":
                self.proc_names[int(fields["pid"])] = fields["name"].rsplit("/", 1)[-1]
            elif kind == "PROCTHREAD_NAME":
                self.thread_names[(int(fields["pid"]), int(fields["tid"]))] = fields["name"]
        except (KeyError, ValueError):
            pass                              # names are a convenience; never fatal

    def name(self, key: Key) -> str:
        """'process/thread' when known, e.g. 'rl_demo/rl_hog0'; else 'pid/tid'."""
        proc, thr = self.proc_names.get(key[0]), self.thread_names.get(key)
        if proc and thr:
            return f"{proc}/{thr}"
        return proc or thr or f"{key[0]}/{key[1]}"

    # -- lookups at a past instant (after parsing) --

    def running_at(self, cpu: int, t: int) -> Running | None:
        times = self._run_t.get(cpu, [])
        i = bisect.bisect_right(times, t) - 1   # last change at or before t
        return self._run_v[cpu][i] if i >= 0 else None

    def state_at(self, key: Key, t: int) -> State | None:
        times = self._st_t.get(key, [])
        i = bisect.bisect_right(times, t) - 1
        return self._st_v[key][i] if i >= 0 else None

    def ready_start(self, key: Key, t: int) -> tuple[int, int] | None:
        """(time, CPU) of the THREADY event that started the READY state the thread is in at t."""
        times, vals = self._st_t.get(key, []), self._st_v.get(key, [])
        i = bisect.bisect_right(times, t) - 1
        while i >= 0 and vals[i][0] == READY:
            if i == 0 or vals[i - 1][0] != READY:
                return times[i], vals[i][2]
            i -= 1
        return None

    def stayed(self, cpu: int, t0: int, t1: int) -> bool:
        """True if one thread was on cpu from t0 through t1 without leaving it.

        Compares threads, not events: a running thread that changes its own
        priority (e.g. SchedSet back to 10 right after MsgReply, in rl_demo's
        inherit mode) is logged as a new THRUNNING on the same CPU without a
        context switch, and must still count as the same stay.
        """
        times, vals = self._run_t.get(cpu, []), self._run_v.get(cpu, [])
        i0, i1 = bisect.bisect_right(times, t0) - 1, bisect.bisect_right(times, t1) - 1
        if i0 < 0 or vals[i0] is None:
            return False
        return all(v is not None and v[:2] == vals[i0][:2] for v in vals[i0 + 1:i1 + 1])

    def changes(self, key: Key, t0: int, t1: int) -> list[int]:
        """Instants strictly inside (t0, t1) where the holder or ANY CPU changes.

        Every CPU, not only the allowed ones: the own-CPU view charges the CPU
        where the holder was made ready, which may be outside the allowed set
        (an earlier version only split at allowed CPUs, and the own view then
        charged whole segments to a stale CPU 0 value; caught by a test).
        """
        pts: set[int] = set()
        for times in [self._st_t.get(key, [])] + list(self._run_t.values()):
            lo, hi = bisect.bisect_right(times, t0), bisect.bisect_left(times, t1)
            pts.update(times[lo:hi])
        return sorted(pts)


@dataclass
class View:
    """One way of charging READY time. Both views share running/blocked buckets."""
    buckets: Counter = field(default_factory=Counter)    # label -> Fraction ticks
    culprits: Counter = field(default_factory=Counter)   # (pid, tid, prio, label) -> Fraction ticks

    def total(self) -> Fraction:
        return sum(self.buckets.values(), Fraction(0))


@dataclass
class Cause:
    """Why a request lost time, from one view. See classify()."""
    name: str                      # one of CAUSES, SERVICE or MIXED
    share: Fraction                # of the lost time; for SERVICE, running time / interval
    lost: Fraction                 # interval - running, in ticks
    by_cause: dict                 # cause -> ticks; adds up exactly to lost
    rule: str | None = None        # the anti-pattern rule, when one applies
    top: str | None = None         # largest cause (differs from name when MIXED)


@dataclass
class Attribution:
    split: View = field(default_factory=View)            # READY split across allowed CPUs
    own: View = field(default_factory=View)              # READY charged to the queued-on CPU
    ready: Counter = field(default_factory=Counter)      # phase -> ticks the holder was READY
    holder_prio: dict = field(default_factory=dict)      # phase -> holder priority (last seen)
    cause: Cause | None = None                           # from the own view (primary)
    cause_split: Cause | None = None                     # from the split view (context only)


def share_label(run: Running | None, holder_prio: int | None, isr: set[Key]) -> str:
    """Label for one CPU's share of a READY instant. The first rule that applies wins."""
    if run is None:
        return "switching"
    pid, tid, prio = run
    if pid == IDLE_PID and prio == IDLE_PRIO:
        return "idle core"
    if (pid, tid) in isr:
        return "interrupt"
    if prio is None or holder_prio is None:
        return "unknown"
    if prio > holder_prio:
        return "higher"
    return "equal" if prio == holder_prio else "lower"


def _charge(view: View, run: Running | None, label: str, amount) -> None:
    view.buckets[label] += amount
    if label in CULPRIT_LABELS and run is not None:
        view.culprits[(run[0], run[1], run[2], label)] += amount


def attribute(phases: list[tuple[str, int, int, Key | None]], tl: Timeline,
              cpus: list[int]) -> Attribution:
    """Split the phases' time into buckets. phases = (name, t0, t1, holder) in
    order and contiguous (each t1 is the next t0)."""
    a = Attribution()
    n = len(cpus)

    def both(label: str, dt: int) -> None:            # time that isn't READY: same in both views
        a.split.buckets[label] += dt
        a.own.buckets[label] += dt

    for name, t0, t1, holder in phases:
        if t1 <= t0:
            continue
        if holder is None:
            both("unknown holder", t1 - t0)
            continue
        pts = [t0] + tl.changes(holder, t0, t1) + [t1]
        for s0, s1 in zip(pts, pts[1:]):
            dt = s1 - s0
            st = tl.state_at(holder, s0)
            if st is None:
                both("unknown", dt)                    # no event for the holder yet
                continue
            state, hprio, _ = st
            if state == RUNNING:
                both("running", dt)
            elif state == READY:
                a.ready[name] += dt
                a.holder_prio[name] = hprio

                def on(cpu: int) -> Running | None:
                    run = tl.running_at(cpu, s0)
                    # Same-instant ordering: the holder can't be READY and running.
                    return None if run is not None and run[:2] == holder else run

                share = Fraction(dt, n)
                for c in cpus:
                    run = on(c)
                    _charge(a.split, run, share_label(run, hprio, tl.isr), share)
                rs = tl.ready_start(holder, s0)
                if rs is None:
                    _charge(a.own, None, "unknown", Fraction(dt))
                    continue
                t_ready, qc = rs
                run = on(qc)
                label = share_label(run, hprio, tl.isr)
                if label == "lower" and tl.stayed(qc, t_ready, s0):
                    label = WAKEUP          # still the thread that was there at the wake-up
                _charge(a.own, run, label, Fraction(dt))
            else:
                both(f"blocked:{state}", dt)
    return a


# -- causes --
#
# A request's LOST time is its interval minus the time its holders were
# running: the time it spent waiting. Each lost tick counts toward one cause:
#
#   priority inversion    the holder was READY behind a thread at or below the
#                         CLIENT's priority that outranked the holder (or equalled
#                         it while the holder was below the client). With the
#                         client's priority the holder would have run. Rule 1 when
#                         the request was handed off to a thread below the client.
#   higher-priority load  behind a thread above the client's priority: legitimate
#                         preemption; inheritance would not have helped.
#   overload              behind an equal-priority thread at the client's priority:
#                         too much work at that level, not a priority bug.
#   not migrated          a lower-priority thread ran (see "lower" above).
#   wake-up switch        own view only: the lower-priority thread that was running
#                         on the holder's CPU when it was made ready ran on until the
#                         switch. Measured: the replier after its MsgReply, ~0.5 us
#                         per request (max 1.4 us, 21 demo traces).
#   other                everything else: idle core, switching, interrupt
#                         threads, blocked states, unknown priorities.
#
# The cause is the one with the largest share of the lost time, or "mixed"
# when none reaches 50%. If the running time alone reaches the deadline, the
# cause is "service time" instead: the work itself is too long.
#
# The PRIMARY cause comes from the own-CPU view, because QNX 8's documented
# scheduling (no cross-CPU displacement) matches it (Marcus, 2026-11-20). The
# split view is classified the same way and reported as context.

INVERSION, LOAD, OVERLOAD, NOT_MIGRATED, OTHER = (
    "priority inversion", "higher-priority load", "overload", "not migrated", "other")
CAUSES = (INVERSION, LOAD, OVERLOAD, NOT_MIGRATED, WAKEUP, OTHER)   # report order
SERVICE, MIXED = "service time", "mixed"
RULE1 = "rule 1: priority inheritance lost at handoff"


def culprit_cause(label: str, prio: int, client_prio: int) -> str:
    """The cause one culprit's ticks count toward. label is relative to the holder."""
    if label == WAKEUP:
        return WAKEUP
    if label == "lower":
        return NOT_MIGRATED
    if prio > client_prio:
        return LOAD
    if label == "higher" or prio < client_prio:   # "equal" below the client: holder < client
        return INVERSION
    return OVERLOAD


def classify(view: View, interval: int, client_prio: int | None, deadline: Fraction | None,
             handoff_below_client: bool) -> Cause:
    """Name the cause of one request's lost time, from one view.

    interval: the request's ticks (resp, or send when there is no release).
    deadline: in ticks, or None. handoff_below_client: 101 and 102 came from
    different threads of the server and the replier ran below the client.
    """
    running = view.buckets.get("running", 0)
    lost = Fraction(interval) - running
    by: Counter = Counter({c: Fraction(0) for c in CAUSES})
    if client_prio is not None:
        for (_, _, prio, label), ticks in view.culprits.items():
            by[culprit_cause(label, prio, client_prio)] += ticks
    by[OTHER] += lost - sum(by.values())          # the rest, so the causes add up to lost
    top = max(CAUSES, key=lambda c: by[c])        # ties: the earlier in CAUSES
    if deadline is not None and running >= deadline:
        return Cause(SERVICE, Fraction(running) / interval if interval else Fraction(0),
                     lost, dict(by), None, top)
    share = by[top] / lost if lost > 0 else Fraction(0)
    name = top if share >= Fraction(1, 2) else MIXED
    rule = RULE1 if name == INVERSION and handoff_below_client else None
    return Cause(name, share, lost, dict(by), rule, top)
