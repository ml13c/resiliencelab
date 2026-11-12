# Kill check:
**Date:** 2026-11-10 (trace header says 2026-09-02: the Pi has no clock battery)
**Hardware:** Raspberry Pi 5, 8 GB
**OS:** QNX 8.0.0, Quick Start Target Image build 50
**Program:** target/ipc_probe/ipc_probe.cpp

here we're just checking if we can follow a request front and back using only kernel trace.

## Setup
- Server at default priority 10, waiting in MsgReceive
- Client at priority 30 (`on -p 30`), 20 requests, 500 µs of work each, every 10 ms
- Trace: `tracelogger -w -s 3` (wide mode, 3 seconds)

## Results
- Client-measured latency: 508.5 to 516.7 µs (500 µs work + about 10 µs overhead)
- All 80 user markers recorded (20 requests × 4 markers)
- Request 1 from the markers (54 MHz clock, 54 ticks = 1 µs):
  - client start → server received: 11.9 µs
  - server work: 501.1 µs
  - server reply → client resumed: 4.4 µs
  - total: 517.4 µs (client measured 516.7 µs, so the clocks agree)
- Priority inheritance is visible two ways:
  - the server reported its own priority as 30 inside the handler
  - the kernel recorded the server THRUNNING at priority 30
- After replying, the server went back to RECEIVE still at priority 30
  (QNX documents that a server keeps the inherited priority after MsgReply)
- REC_MESSAGE detail lines (info->pid, info->tid) identify the sender,
  so client-to-server links can be rebuilt

## Conclusion
Kill check passed. Everything the analyzer needs is in the trace.
Always trace with `-w`; priorities only appear in wide mode.

## Next
actually making the Analyzer v0: rebuild the request table automatically for all 20 requests.