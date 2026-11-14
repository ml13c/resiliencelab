# Demo capture 1: all scenarios traced (unaligned hog)
**Date:** captured and copied 2026-11-13 (the Pi has no RTC).
**Hardware:** Raspberry Pi 5, 8 GB. QNX 8.0.0, Quick Start Target Image build 50.
**Program:**
- target/rl_demo/rl_demo.cpp, with the fixed-rate client (7 ms releases) and the FIRST hog version (each thread sleeps 2 ms after its own 8 ms busy spell, threads not aligned).
- target/rl_demo/run_demo.sh, FIRST version: tracelogger at prio 50 wrote to /tmp.

**Command:** `sh run_demo.sh all` as root.
**Files:**
- `<name>.kev` is the raw trace.
- `<name>.*.log` are the program outputs (renamed from .txt, which is gitignored).
- `<name>.txt` (traceprinter) is gitignored and can be regenerated.

Client: prio 30, 200 requests, 500 µs work, 7 ms period, 2000 µs deadline. Hogs: busy 8 ms / idle 2 ms, RR unless noted. Every tracelogger log is empty: no errors reported.

## Client results (measured)
| Scenario | Server | Hog | Late | Skipped | Min / median / max µs |
|---|---|---|---|---|---|
| baseline | handoff | none | 0/200 | 0 | 511.4 / 514.8 / 521.9 |
| defect | handoff | 4×20 | 18/200 | 0 | 510.2 / 515.6 / 2648.6 |
| defect_cpu0 | handoff | 1×20, all on CPU 0 | **173/200** | 113 | 509.3 / 4608.7 / 8523.9 |
| fixed | inherit | 4×20 | 0/200 | 0 | 511.3 / 516.4 / 620.6 |
| fixed_direct | direct | 4×20 | 0/200 | 0 | 506.9 / 509.6 / 611.2 |
| control_rr | inherit | 4×30 RR | 21/200 | 0 | 512.2 / 517.3 / 4508.5 |
| control_fifo | inherit | 4×30 FIFO | 0/200 | 0 | 511.8 / 516.5 / 622.4 |

All runs: functional 200/200 correct, client exit 0.

## Trace measurements
Measured with a scratch per-CPU timeline script, not yet part of the analyzer. The window runs from the first marker 100 to the last marker 103.

| Scenario | Hog-busy per CPU | All 4 CPUs hog-busy | Longest all-4 stretch | Worker THRUNNING priority |
|---|---|---|---|---|
| defect | 67–75% | 18% | 1.00 ms | 10 only |
| control_rr | 70–75% | 36% | 2.99 ms | 30 (and 10, see below) |
| control_fifo | 66–78% | **0%** (3 CPUs: 90%) | 0.02 ms | 30 (and 10) |
| fixed | 71–72% | 50% | 2.00 ms | 30 (and 10) |
| defect_cpu0 | 72% of CPU 0 | n/a | n/a | 10 only |

Notes on the table:
- The THRUNNING-at-10 events in inherit mode come after the reset: the worker drops to 10 and runs briefly at 10 until it blocks in the condvar wait. Their count is ≈ 2 per request.
- The policy logged for the hog threads in THRUNNING matches the setting: 2 (RR), and 1 (FIFO) in control_fifo.

## Observations
- **Measured: the multi-core hog rarely saturates all cores.** The four hog threads drift apart, so in the defect run a core is almost always free. All 4 were busy only 18% of the time, never longer than 1 ms. The prio-10 worker finds a gap quickly: only 18/200 late.
  - Cause: each thread sleeps relative to the end of its own busy spell, and the threads are never re-aligned.
  - Fix in the hog: all threads follow one absolute schedule (`--unaligned` keeps the old behaviour).
- **Measured: with the FIFO hogs, exactly 3 of 4 CPUs were busy 90% of the time,** never all 4. So there was no contention and 0 late. The mechanism of that 3-of-4 pattern is a hypothesis: a FIFO hog that wakes while all cores are taken waits for one to free up, so the threads rotate.
- **Measured: the pinned defect is the strong demo,** with 173/200 late and 113 releases skipped.
- **Measured: tracing perturbs the chain.** In the slowest `fixed` request (621.3 µs), these ran on the worker's CPU 3 inside the request:
  - pid 28677 `devb-sdmmc-bcm2712` (SD card driver) at prio 50 for 88.4 µs
  - `tracelogger` itself at prio 50 for about 12 µs

  tracelogger wrote the trace to /tmp, on the SD card, and the driver served those writes at tracelogger's priority. Fix in run_demo.sh: the capture goes to /dev/shmem (RAM) and is moved afterwards.
- **Supported:** the fixed-rate client removed the phase-locking seen in the untraced run.
  - The defect went from 200/200 late clustered at ~3.5 ms to 18/200 with a wide spread.
  - Hog alignment also differs between the two runs, so this isn't a clean single-variable comparison.

## Next
Re-capture with the aligned hog and the RAM trace file. The client now also prints its release delay, because in the control the client itself may wait before marker 100. That wait is invisible to the trace interval.
