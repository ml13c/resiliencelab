#!/bin/sh
# run_demo.sh - capture ResilienceLab demo scenarios with kernel tracing (QNX 8.0).
# Run as root (kernel tracing needs it), from ~/bin:
#
#   sh run_demo.sh <name> <handoff|inherit|direct> <hog prio, 0 = no hog> [--fifo] [--cpu N]
#   sh run_demo.sh all        # every planned scenario, one after another
#   sh run_demo.sh repeat N   # repeatability + tracing overhead: N rounds of 5
#                             # scenarios, each traced and untraced (~11 min for N=10)
#
# Output in /tmp/rl: <name>.kev (raw trace, the file to keep), <name>.txt
# (traceprinter; gitignored, can be regenerated), <name>.meta (scenario metadata)
# and <name>.{client,server,hog,tracelogger}.log.
# The logs are .log, not .txt, because traces/**/*.txt is gitignored.
# Copy back from Windows:  scp -r qnxpi:/tmp/rl traces\<date>-demo
# repeat writes to /tmp/rl_repeat instead and makes no .txt (see run_repeat).
set -u
B=/data/home/qnxuser/bin
OUT=/tmp/rl
# Per-run settings; only the repeat mode changes them.
SCEN=""      # scenario name for .meta (default: the run name)
TRACE=1      # 0 = no tracelogger: the run is measured by the client alone
ROUND=""     # repeat round number, recorded in .meta
TXT=1        # 0 = skip traceprinter on the Pi (convert the .kev on Windows)

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
    trace=on; [ "$TRACE" = 0 ] && trace=off
    echo "== $name: server $mode, hog prio $hogprio $opts, trace $trace"
    # Scenario metadata for the analyzer. cpus= is the set of cores the request's
    # threads may use: the --cpu N passed to every role, else all. The analyzer
    # reads <name>.meta next to <name>.txt instead of guessing from the trace.
    cpus=all prev=""
    for o in $opts; do
        [ "$prev" = --cpu ] && cpus=$o
        prev=$o
    done
    printf 'scenario=%s\nserver_mode=%s\nhog_prio=%s\noptions=%s\ncpus=%s\ntrace=%s\n' \
        "${SCEN:-$name}" "$mode" "$hogprio" "$opts" "$cpus" "$trace" > $OUT/$name.meta
    if [ -n "$ROUND" ]; then echo "round=$ROUND" >> $OUT/$name.meta; fi

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
    tl=""
    if [ "$TRACE" != 0 ]; then
        on -p 50 tracelogger -w -s 4 -f $ram > $OUT/$name.tracelogger.log 2>&1 &
        tl=$!
    fi
    # The same pause traced or not, so the hog has run equally long when the client starts.
    sleep 1                         # let tracelogger start before the first request
    on -p 30 $B/rl_demo client 0 200 500 7 2000 $opts > $OUT/$name.client.log 2>&1
    rc=$?
    if [ -n "$tl" ]; then wait $tl; fi   # tracelogger stops by itself after 4 s
    kill $srv $hog 2>/dev/null      # by PID: slay asks y/N when the tty is unknown
    wait 2>/dev/null
    if [ "$TRACE" = 0 ]; then
        :                           # untraced: the client log is the measurement
    elif [ ! -s $ram ]; then
        echo "   NO TRACE in $ram; see $OUT/$name.tracelogger.log" >&2
    else
        mv $ram $OUT/$name.kev
        if [ "$TXT" != 0 ]; then $B/traceprinter -f $OUT/$name.kev > $OUT/$name.txt; fi
    fi
    tail -n 7 $OUT/$name.client.log
    echo "   client exit $rc, trace $(wc -c < $OUT/$name.kev 2>/dev/null || echo 0) bytes"
}

# Repeatability + tracing overhead: N rounds; in each, every scenario runs once
# traced and once untraced. The order flips every round (odd: traced first, even:
# untraced first), so slow drift (temperature, memory) and "which ran first"
# don't line up with tracing. No traceprinter here: 50 .txt files would be
# ~1.4 GB on the SD card; the .kev files (~8 MB each) are converted on Windows.
run_repeat() {
    n=$1
    OUT=/tmp/rl_repeat
    TXT=0
    mkdir -p $OUT
    df -k /tmp
    free_kb=$(df -k /tmp 2>/dev/null | awk 'NR == 2 {print $4}')
    case "$free_kb" in
        ''|*[!0-9]*) echo "   could not read free space for /tmp; check the df output above" >&2 ;;
        *) if [ "$free_kb" -lt 1048576 ]; then
               echo "only $free_kb KB free for /tmp; the traces need ~400 MB (want 1 GB)" >&2
               exit 1
           fi ;;
    esac
    r=1
    while [ $r -le $n ]; do
        ROUND=$r
        rr=$(printf %02d $r)
        if [ $((r % 2)) = 1 ]; then order="1 0"; else order="0 1"; fi
        for spec in "baseline handoff 0" "defect handoff 20" "fixed inherit 20" \
                    "control_rr inherit 30" "control_fifo inherit 30 --fifo"; do
            set -- $spec
            SCEN=$1
            for TRACE in $order; do
                tag=on; [ "$TRACE" = 0 ] && tag=off
                run_one "$SCEN.r$rr.$tag" "$2" "$3" ${4:-}
            done
        done
        r=$((r + 1))
    done
    echo "== repeat done: $n rounds in $OUT"
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
if [ "${1:-}" = repeat ]; then
    case "${2:-}" in
        ''|*[!0-9]*|0) echo "usage: sh run_demo.sh repeat N   (N >= 1)" >&2; exit 2 ;;
    esac
    run_repeat "$2"
    exit 0
fi
if [ $# -lt 3 ]; then
    echo "usage: sh run_demo.sh <name> <handoff|inherit|direct> <hog prio|0> [--fifo] [--cpu N]" >&2
    echo "       sh run_demo.sh all" >&2
    echo "       sh run_demo.sh repeat N" >&2
    exit 2
fi
run_one "$@"
