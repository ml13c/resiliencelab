#!/bin/sh
# run_demo.sh - capture ResilienceLab demo scenarios with kernel tracing (QNX 8.0).
# Run as root (kernel tracing needs it), from ~/bin:
#
#   sh run_demo.sh <name> <handoff|inherit|direct> <hog prio, 0 = no hog> [--fifo] [--cpu N]
#   sh run_demo.sh all        # every planned scenario, one after another
#
# Output in /tmp/rl: <name>.kev (raw trace, the file to keep), <name>.txt
# (traceprinter; gitignored, can be regenerated), and <name>.{client,server,hog,tracelogger}.log.
# The logs are .log, not .txt, because traces/**/*.txt is gitignored.
# Copy back from Windows:  scp -r qnxpi:/tmp/rl traces\<date>-demo
set -u
B=/data/home/qnxuser/bin
OUT=/tmp/rl

# The hogs keep every core busy at priority 20 or 30. Anything at the default
# priority 10, including this shell, would only run in the hogs' idle gaps.
# So re-run this script at priority 40. That doesn't leak into the scenario:
# the server sets its own base priority (10), the worker and hog threads use
# explicit priorities, and the client is started with on -p 30.
if [ -z "${RL_ELEVATED:-}" ]; then
    export RL_ELEVATED=1
    exec on -p 40 sh "$0" "$@"
fi

run_one() {
    name=$1 mode=$2 hogprio=$3
    shift 3
    opts="$*"                       # --cpu N / --fifo, passed to every role
    mkdir -p $OUT
    rm -f $OUT/$name.*
    echo "== $name: server $mode, hog prio $hogprio $opts"

    $B/rl_demo server $mode $opts > $OUT/$name.server.log 2>&1 &
    srv=$!
    sleep 1                         # let name_attach finish before the client looks it up
    hog=""
    if [ "$hogprio" -gt 0 ]; then
        # 8 s covers the whole capture: hog starts at ~1 s, trace runs ~2-6 s.
        $B/rl_demo hog 0 $hogprio 8 2 8 $opts > $OUT/$name.hog.log 2>&1 &
        hog=$!
        sleep 1
    fi
    # tracelogger runs above the hogs too, so its buffer writer isn't starved
    # (that could lose events). It writes to RAM (/dev/shmem), not /tmp: /tmp is
    # on the SD card, and the SD driver serves tracelogger's writes at
    # tracelogger's priority (50). In the first capture that preempted the
    # prio-30 worker for 88 us. The file moves to /tmp/rl after the capture.
    ram=/dev/shmem/rl_$name.kev
    rm -f $ram
    on -p 50 tracelogger -w -s 4 -f $ram > $OUT/$name.tracelogger.log 2>&1 &
    tl=$!
    sleep 1                         # let tracelogger start before the first request
    on -p 30 $B/rl_demo client 0 200 500 7 2000 $opts > $OUT/$name.client.log 2>&1
    rc=$?
    wait $tl                        # tracelogger stops by itself after 4 s
    kill $srv $hog 2>/dev/null      # by PID: slay asks y/N when the tty is unknown
    wait 2>/dev/null
    if [ ! -s $ram ]; then
        echo "   NO TRACE in $ram; see $OUT/$name.tracelogger.log" >&2
    else
        mv $ram $OUT/$name.kev
        $B/traceprinter -f $OUT/$name.kev > $OUT/$name.txt
    fi
    tail -n 6 $OUT/$name.client.log
    echo "   client exit $rc, trace $(wc -c < $OUT/$name.kev 2>/dev/null || echo 0) bytes"
}

if [ "${1:-}" = all ]; then
    run_one baseline     handoff 0
    run_one defect       handoff 20
    run_one defect_cpu0  handoff 20 --cpu 0
    run_one fixed        inherit 20
    run_one fixed_direct direct  20
    run_one control_rr   inherit 30
    run_one control_fifo inherit 30 --fifo
    exit 0
fi
if [ $# -lt 3 ]; then
    echo "usage: sh run_demo.sh <name> <handoff|inherit|direct> <hog prio|0> [--fifo] [--cpu N]" >&2
    echo "       sh run_demo.sh all" >&2
    exit 2
fi
run_one "$@"
