# Demo capture 3: TIMER_PRECISE sleeps, no in-loop printing
**Date:** copied 2026-11-14 (the Pi has no RTC).
**Hardware:** Raspberry Pi 5, 8 GB. QNX 8.0.0, Quick Start Target Image build 50.
**Program:**
- target/rl_demo/rl_demo.cpp: aligned hog, fixed-rate client (7 ms), results printed after the loop, sleeps with TIMER_PRECISE.
- run_demo.sh: tracelogger at prio 50 writing to /dev/shmem.

**Command:** `sh run_demo.sh all` as root.
**Files:** `<name>.kev` (raw trace) and `<name>.*.log`. `<name>.txt` is gitignored and regenerable.

The first copy was interrupted, and the second `scp -r` nested everything under `rl/`. I flattened the folder on 2026-11-14:
- The top-level baseline files from the interrupted copy were identical (.kev, .log), except baseline.txt, which was truncated at 10 of 28 MB.
- The complete copies were kept.

## Results
The client columns are measured by the client; the analyzer columns are rl_analyze.py on the trace.

| Scenario | Server | Hog | Client late (from send) | Analyzer late from send | **Analyzer late from release (verdict)** | Skipped | Kernel wait median / max µs | Replier prio |
|---|---|---|---|---|---|---|---|---|
| baseline | handoff | none | 0 | 0 | **0** | 0 | 3.4 / 8.0 | 10 |
| defect | handoff | 4×20 | 175 | 175 | **175** | 50 | 3.3 / 8.7 | 10 |
| defect_cpu0 | handoff | 1×20, CPU 0 | 175 | 175 | **175** | 50 | 2.8 / 81.0 | 10 |
| fixed | inherit | 4×20 | 0 | 0 | **0** | 0 | 3.6 / 16.2 | 30 |
| fixed_direct | direct | 4×20 | 0 | 0 | **0** | 0 | 3.3 / 74.5 | 30 |
| control_rr | inherit | 4×30 RR | 100 | 102 | **126** | 0 | 7.0 / 3004.0 | 30 |
| control_fifo | inherit | 4×30 FIFO | 16 | 16 | **148** | 49 | 3156.2 / 7154.8 | 30 |

Notes on the table:
- Out of 200 requests each. All runs: functional 200/200 correct, client exit 0, no analyzer warnings, every tracelogger log empty.
- "Kernel wait" = the client's wake (THNANOSLEEP → THREADY) to marker 100.
- Request 1 has no preceding sleep, so it has no release and is judged on send (1 per scenario).

## Observations
- **Measured: the demo works end to end.** Every reply is correct.
  - With the handoff defect, 175/200 requests are late under prio-20 hogs, on 4 cores or pinned to one, with the worker at 10.
  - Both fixes give 0/200 late, with the replier at 30.
- **Measured: the release-based verdict exposes the controls.**
  - control_fifo is 16 late from send but 148 from release.
  - The client itself, at prio 30, waits a median 3.2 ms (max 7.2 ms) behind FIFO hogs at 30 before it can even send.
  - In the defect and fixed runs the wait stays at microseconds, because the client outranks the prio-20 hogs.
- **Measured: TIMER_PRECISE is accepted on this image but has no visible effect.**
  - The kernel wait (timer wake → send) is ~3 µs, but the client's "release delay" (scheduled → send) is still a constant per run (baseline 460 µs, fixed_direct 789 µs). So the timer still fires a fixed few hundred µs after the scheduled time.
  - The kernel-based release doesn't depend on this. The client's message now says "accepted (no effect measured)".
- **Measured: the client and the trace agree on send latency, apart from requests within ~1 µs of the deadline.**
  - control_rr: 100 late on the client vs 102 in the trace. Those two requests are 2000.5 / 2000.8 µs in the trace and 1999.7 / 1999.9 µs on the client.
  - The client starts its clock after marker 100 and stops it before 103, the same ~0.7 µs gap as in the kill check.
  - control_rr clusters right at 2 ms, so its count is deadline-sensitive.
- **Hypothesis:** why the defect has 87.5% late instead of my predicted 65–70%. Skipped releases may bias which hog phases get sampled. Not analysed.

## Next
The kernel-event autopsy: attribute each late request's wait to the threads that ran instead.
