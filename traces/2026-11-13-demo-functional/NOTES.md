# Demo slice 1: functional check (untraced)
**Date:** results received 2026-11-13. The Pi has no RTC, so its clock can't date the run.
**Hardware:** Raspberry Pi 5, 8 GB. QNX 8.0.0, Quick Start Target Image build 50.
**Program:** target/rl_demo/rl_demo.cpp (slice 1: server handoff | direct, client)

Purpose: check that every request gets a correct reply in both server modes, with no load. No tracelogger ran, so there is no .kev for this experiment.

## Setup (root shell)
    B=/data/home/qnxuser/bin
    $B/rl_demo server handoff &          # then again with: direct
    on -p 30 $B/rl_demo client 0 200 500 7 2000 | tail -n 3
    slay rl_demo
Server receive thread at the default priority 10. In handoff mode, the worker is fixed at 10. Client at 30: 200 requests, 500 µs work, 7 ms period, 2000 µs deadline.

## Results (client-measured, verbatim)
handoff:
    functional: 200/200 correct
    deadline 2000 us: 0/200 late (client-measured)
    latency us: min 508.2  median 510.4  max 521.9
direct:
    functional: 200/200 correct
    deadline 2000 us: 0/200 late (client-measured)
    latency us: min 504.3  median 506.4  max 513.6

## Observations
- Both modes are functionally correct, and nothing is late without a hog. The defect is latent.
- The handoff costs about 4.0 µs at the median and 8.3 µs at the max (one run each, so no repeatability yet).
- The direct-mode median of 506.4 µs is in line with the kill check's 508.5–516.7 µs. The kill check used a 10 ms period, so this isn't a like-for-like comparison.
- TraceEvent calls with no tracelogger running did no harm.

## Next
Slice 2: inherit mode, hog role, `--cpu`. Then untraced runs under the hog.
