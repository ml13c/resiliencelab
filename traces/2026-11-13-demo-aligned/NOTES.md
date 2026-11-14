# Demo capture 2: aligned hog, trace written to RAM
**Date:** copied 2026-11-14 (the Pi has no RTC).
**Hardware:** Raspberry Pi 5, 8 GB. QNX 8.0.0, Quick Start Target Image build 50.
**Program:**
- target/rl_demo/rl_demo.cpp with the aligned hog (all threads busy for the first 8 ms of every 10 ms) and the fixed-rate client (7 ms). This client still printed each request inside the loop, and still used tick-based sleeps.
- run_demo.sh with tracelogger at prio 50, writing to /dev/shmem.

**Command:** `sh run_demo.sh all` as root.
**Files:** `<name>.kev` (raw trace) and `<name>.*.log`. `<name>.txt` is gitignored and regenerable.

## Client results (measured)
| Scenario | Server | Hog | Late | Skipped | Min / median / max µs | Release delay median / max µs |
|---|---|---|---|---|---|---|
| baseline | handoff | none | 0/200 | 0 | 511.3 / 514.6 / 522.3 | 38.1 / 42.9 |
| defect | handoff | 4×20 | **175/200** | 50 | 511.4 / 5185.8 / 8187.2 | 194.5 / 203.9 |
| defect_cpu0 | handoff | 1×20, CPU 0 | **150/200** | 50 | 509.6 / 4860.3 / 7863.1 | 617.8 / 691.1 |
| fixed | inherit | 4×20 | 0/200 | 28 | 511.9 / 516.6 / 592.1 | 108.0 / 115.6 |
| fixed_direct | direct | 4×20 | 0/200 | 0 | 506.9 / 509.6 / 587.5 | 814.9 / 882.8 |
| control_rr | inherit | 4×30 RR | 107/200 | 0 | 514.1 / 2002.8 / 5657.8 | 136.6 / 2134.8 |
| control_fifo | inherit | 4×30 FIFO | 9/200 | 116 | 513.6 / 519.9 / 8141.4 | **3774.0 / 7774.2** |

All runs: functional 200/200 correct, client exit 0. Every tracelogger log is empty.

## Observations
- **Measured: the aligned hog makes the multi-core defect strong.** 175/200 late (capture 1: 18/200), and the fixes stay at 0 late.
  - That is more than my 65–70% prediction. Hypothesis: skipped releases bias which hog phases get sampled. Not analysed yet.
- **Measured: the timer tick is 1 ms.** Timer interrupts (intr 0x1b) on CPU 0 in the baseline come at exact multiples of 1000 µs: 1166 gaps of 1 ms, 520 of 2 ms, 373 of 3 ms…; longer gaps while idle.
  - So every non-control "release delay" is a near-constant offset below 1 ms: the schedule's start phase relative to the tick, not waiting.
  - Fix: the client and hog now sleep with TIMER_PRECISE, falling back to the tick if it's rejected.
- **Measured: the `fixed` run's 28 skipped releases came from the client's own logging.**
  - The client was REPLY-blocked for 163.5 ms and 41.5 ms (28 ≈ (163 + 41) / 7) in MsgSend to pid 28677 `devb-sdmmc-bcm2712`. That was its printf, writing to the log file on the SD card.
  - The driver thread serving it (tid 10, raised to 30) waited on a semaphore. The driver's other threads ran normally at 21 / 40 / 254, above the hogs.
  - Hypothesis: an SD card write stall, not CPU starvation.
  - Fix: the client keeps results in memory and prints after the loop.
- **Measured: the control's waiting is mostly invisible in the request interval.**
  - control_fifo: 9/200 late from send, but release delay median 3.8 ms, max 7.8 ms, and 116 skipped. The client itself (prio 30) waits behind the FIFO hogs (prio 30) *before* marker 100.
  - control_rr clusters right at the 2 ms deadline (median 2002.8 µs), so its late count is very sensitive to the deadline value.
- **Measured: tracing overhead is still present but smaller.** In the slowest `fixed` request (592.9 µs, request 3), procnto pid 1 tid 26 ran on the worker's CPU at prio 50 for 60.4 µs. Hypothesis: it was serving tracelogger's writes to /dev/shmem. In capture 1 it was devb-sdmmc for 88 µs. Left for the tracing-overhead measurement milestone.

## Next
Capture 3, with TIMER_PRECISE sleeps and no in-loop printing. In the analyzer slice, measure lateness from the client's *release*: its THNANOSLEEP → THREADY transition in the kernel trace, before marker 100, so the control's pre-send wait counts.
