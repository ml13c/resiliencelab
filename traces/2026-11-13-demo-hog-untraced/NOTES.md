# Demo slice 2: scenarios under CPU hogs (untraced)
**Date:** results received 2026-11-13 (the Pi has no RTC).
**Hardware:** Raspberry Pi 5, 8 GB. QNX 8.0.0, Quick Start Target Image build 50.
**Program:** target/rl_demo/rl_demo.cpp, slice 2, with the FIRST client version: it sleeps 7 ms *after* each reply. No tracelogger ran, so there is no .kev.

## Setup (root shell started with `on -p 40 sh`)
For each run:
1. `rl_demo server <mode> [--cpu 0] &`
2. `rl_demo hog 0 <prio> 8 2 8 [--cpu 0] &`
3. `on -p 30 rl_demo client 0 200 500 7 2000 [--cpu 0]`
4. `slay rl_demo`

Hog: 4 threads (1 when pinned), RR, busy 8 ms / idle 2 ms. Client: 200 requests, 500 µs work, 2000 µs deadline.

## Results (client-measured)
| Run | Server | Hog | Functional | Late | Min / median / max µs |
|---|---|---|---|---|---|
| defect | handoff | 4×20 | 200/200 | **200/200** | 3506.8 / 3511.8 / 6458.6 |
| fix 1 | inherit | 4×20 | 200/200 | 0/200 | 508.1 / 511.2 / 523.1 |
| fix 2 | direct | 4×20 | 200/200 | 0/200 | 504.6 / 506.6 / 510.4 |
| control | inherit | 4×**30** | 200/200 | **0/200** | 510.9 / 1502.9 / 1574.4 |
| defect pinned | handoff | 1×20 on CPU 0 | 200/200 | **200/200** | 3499.7 / 3504.6 / 8321.1 |

## Observations
- **Measured: the demo's core claim holds.** With the handoff defect under a prio-20 hog, every reply is correct, yet 200/200 miss the deadline. Pinned to one core gives the same result.
- **Measured: both fixes remove every miss.**
  - fix 1 costs about 1 µs over the no-hog handoff median (511.2 vs 510.4, slice 1).
  - fix 2 costs nothing measurable (506.6 vs 506.4).
- **Measured: the RR control does not miss the 2 ms deadline.** But it sits at a steady ~1.5 ms, about 1 ms of waiting among equal-priority threads. Why it is ~1 ms is unknown and needs the trace.
- **Hypothesis: the defect's tight cluster at ~3.5 ms comes from phase-locking, not from the defect's natural spread.**
  - The client slept 7 ms *after each reply*, and the hog decided when the reply came. So the client's schedule fell into step with the hog's cycle and every request hit the same phase.
  - Consequence: this client fixed the miss rate at 100% by construction.
  - Fixed in the client, which now releases on a fixed 7 ms schedule. To confirm: the late fraction and the latency spread should change.
- **Operational:** `slay` asked y/N for every process ("tty not known"). run_demo.sh kills by PID instead.

## Next
Traced captures of all scenarios with run_demo.sh and the fixed-rate client. Includes `control_fifo` (hogs at 30, SCHED_FIFO): FIFO hogs keep a core until they sleep, so equal-priority waiting can reach their 8 ms busy time.
