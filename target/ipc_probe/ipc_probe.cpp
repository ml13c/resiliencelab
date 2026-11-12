// ipc_probe.cpp - ResilienceLab kill-check probe for QNX 8.0
//
// One executable, two roles:
//   ipc_probe server                                  - receives requests, busy-works, replies
//   ipc_probe client [count] [work_us] [period_ms]    - sends numbered requests, times each one
//
// Every request is bracketed with user trace events so it can be found in a
// tracelogger capture alongside the kernel's own scheduling and IPC events.
//
// Build (Windows, after qnxsdp-env.bat):
//   qcc -Vgcc_ntoaarch64le -lang-c++ -O2 -Wall ipc_probe.cpp -o ipc_probe

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cerrno>
#include <unistd.h>
#include <pthread.h>
#include <sys/neutrino.h>
#include <sys/dispatch.h>
#include <sys/iomsg.h>
#include <sys/syspage.h>
#include <sys/trace.h>

static const char*    kName    = "rl_probe";
static const uint16_t kMsgType = _IO_MAX + 1;   // stay clear of the system's _IO_* message range

// User trace event codes (our own markers in the kernel trace).
enum : int {
    EV_REQ_START = 100,   // client: about to MsgSend request N
    EV_SRV_GOT   = 101,   // server: received request N
    EV_SRV_REPLY = 102,   // server: about to reply to request N
    EV_REQ_END   = 103,   // client: MsgSend for request N returned
};

struct Request { uint16_t type; uint16_t pad; uint32_t id; uint32_t work_us; };
struct Reply   { uint32_t id; uint32_t status; };

union RecvBuf {
    uint16_t      type;    // every non-pulse message starts with a 16-bit type
    struct _pulse pulse;
    Request       req;
};

// Burn CPU for 'us' microseconds, so the work shows up as RUNNING time in the trace.
// ClockCycles() reads the same 54 MHz counter that stamps trace events on the Pi.
static void spin_us(uint32_t us) {
    const uint64_t cps = SYSPAGE_ENTRY(qtime)->cycles_per_sec;
    const uint64_t end = ClockCycles() + (cps * us) / 1000000ULL;
    while (ClockCycles() < end) { }
}

static int my_priority() {
    sched_param sp{};
    int policy = 0;
    pthread_getschedparam(pthread_self(), &policy, &sp);
    return sp.sched_priority;
}

static int run_server() {
    // name_attach creates a channel and registers it as /dev/name/local/rl_probe,
    // so clients can find it by name instead of needing our pid and channel id.
    name_attach_t* att = name_attach(nullptr, kName, 0);
    if (!att) { perror("name_attach"); return 1; }
    printf("server: pid %d priority %d, listening as '%s'\n", getpid(), my_priority(), kName);
    fflush(stdout);

    RecvBuf msg;
    for (;;) {
        // Blocks in RECEIVE state until a message or pulse arrives.
        int rcvid = MsgReceive(att->chid, &msg, sizeof msg, nullptr);
        if (rcvid == -1) { perror("MsgReceive"); break; }

        if (rcvid == 0) {                       // a pulse, not a message
            if (msg.pulse.code == _PULSE_CODE_DISCONNECT) ConnectDetach(msg.pulse.scoid);
            continue;
        }
        if (msg.type == _IO_CONNECT) {          // sent by the client's name_open()
            MsgReply(rcvid, EOK, nullptr, 0);
            continue;
        }
        if (msg.type != kMsgType) { MsgError(rcvid, ENOSYS); continue; }

        // From here until MsgReply, this thread runs at the CLIENT's priority
        // (QNX priority inheritance). The trace should show that.
        TraceEvent(_NTO_TRACE_INSERTSUSEREVENT, EV_SRV_GOT, (int)msg.req.id, my_priority());
        spin_us(msg.req.work_us);
        TraceEvent(_NTO_TRACE_INSERTSUSEREVENT, EV_SRV_REPLY, (int)msg.req.id, 0);

        Reply r{msg.req.id, 0};
        MsgReply(rcvid, EOK, &r, sizeof r);     // unblocks the client
    }
    name_detach(att, 0);
    return 0;
}

static int run_client(int count, uint32_t work_us, uint32_t period_ms) {
    int coid = name_open(kName, 0);             // connection to the server's channel
    if (coid == -1) { perror("name_open"); return 1; }

    const double cps = (double)SYSPAGE_ENTRY(qtime)->cycles_per_sec;
    printf("client: pid %d priority %d, %d requests, work %u us, period %u ms\n",
           getpid(), my_priority(), count, work_us, period_ms);

    for (int i = 1; i <= count; ++i) {
        Request req{kMsgType, 0, (uint32_t)i, work_us};
        Reply   rep{};

        TraceEvent(_NTO_TRACE_INSERTSUSEREVENT, EV_REQ_START, i, 0);
        uint64_t t0 = ClockCycles();
        // MsgSend blocks: SEND-blocked until the server receives,
        // then REPLY-blocked until the server replies.
        if (MsgSend(coid, &req, sizeof req, &rep, sizeof rep) == -1) { perror("MsgSend"); break; }
        uint64_t t1 = ClockCycles();
        TraceEvent(_NTO_TRACE_INSERTSUSEREVENT, EV_REQ_END, i, 0);

        printf("req %2d: %8.1f us\n", i, (double)(t1 - t0) * 1e6 / cps);
        delay(period_ms);                       // QNX: sleep for period_ms milliseconds
    }
    name_close(coid);
    return 0;
}

int main(int argc, char** argv) {
    if (argc >= 2 && strcmp(argv[1], "server") == 0) return run_server();
    if (argc >= 2 && strcmp(argv[1], "client") == 0) {
        int      n = argc > 2 ? atoi(argv[2]) : 20;
        uint32_t w = argc > 3 ? (uint32_t)atoi(argv[3]) : 500;
        uint32_t p = argc > 4 ? (uint32_t)atoi(argv[4]) : 10;
        return run_client(n, w, p);
    }
    fprintf(stderr, "usage: %s server | client [count] [work_us] [period_ms]\n", argv[0]);
    return 2;
}
