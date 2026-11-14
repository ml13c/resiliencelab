// rl_demo.cpp - ResilienceLab demo workload for QNX 8.0
//
// Demonstrates anti-pattern rule 1: "priority inheritance lost at handoff".
//
//   rl_demo server handoff    receive thread queues each request to a fixed
//                             priority-10 worker (queue + condvar)  <- the defect
//   rl_demo server inherit    same handoff, but the worker is raised to the
//                             client's priority                     <- fix 1
//   rl_demo server direct     receive thread does the work itself  <- fix 2 (idiomatic QNX)
//   rl_demo client [index] [count] [work_us] [period_ms] [deadline_us]
//                             sends numbered requests, checks every reply,
//                             reports deadline misses
//   rl_demo hog [threads] [prio] [busy_ms] [idle_ms] [seconds] [--fifo]
//                             CPU load: each thread spins busy_ms, sleeps idle_ms
//
// Any role takes --cpu N: every thread of that process runs only on CPU N.
//
// Markers (same codes as ipc_probe; d1 values of 0 mean "not reported"):
//   100 client request start   d0 = request id   d1 = deadline in us
//   101 server received        d0 = request id   d1 = receiving thread's priority
//   102 server about to reply  d0 = request id   d1 = replying thread's priority
//   103 client got reply       d0 = request id   d1 = 1 reply correct, 2 wrong
// Request id = client index << 24 | sequence number, so ids are unique per run
// even with several clients.
//
// Build (Windows, after qnxsdp-env.bat):
//   q++ -Vgcc_ntoaarch64le -O2 -Wall target\rl_demo\rl_demo.cpp -o rl_demo

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <pthread.h>
#include <sched.h>
#include <time.h>
#include <unistd.h>
#include <sys/dispatch.h>
#include <sys/iomsg.h>
#include <sys/neutrino.h>
#include <sys/syspage.h>
#include <sys/trace.h>

static const char*    kName           = "rl_demo";
static const uint16_t kMsgType        = _IO_MAX + 1;   // clear of the system's _IO_* range
static const int      kServerBasePrio = 10;            // receive thread's own priority
static const int      kWorkerPrio     = 10;            // the worker's base priority (the defect)

static int g_cpu = -1;   // --cpu N, or -1 = run anywhere

// Restrict the calling thread to CPU g_cpu (no-op without --cpu). Called by
// every thread at its start, so a whole process can be confined to one core.
static void pin_self() {
    if (g_cpu < 0) return;
    if (ThreadCtl(_NTO_TCTL_RUNMASK, (void*)(uintptr_t)(1u << g_cpu)) == -1)
        perror("ThreadCtl(_NTO_TCTL_RUNMASK)");
}

enum : int {
    EV_REQ_START = 100,
    EV_SRV_GOT   = 101,
    EV_SRV_REPLY = 102,
    EV_REQ_END   = 103,
};

struct Request { uint16_t type; uint16_t pad; uint32_t id; uint32_t work_us; uint32_t input; };
struct Reply   { uint32_t id; uint32_t status; uint32_t result; };

union RecvBuf {
    uint16_t      type;    // every non-pulse message starts with a 16-bit type
    struct _pulse pulse;
    Request       req;
};

static void mark(int code, uint32_t d0, int d1) {
    TraceEvent(_NTO_TRACE_INSERTSUSEREVENT, code, (int)d0, d1);
}

// Burn CPU for 'us' microseconds, so the work shows up as RUNNING time in the trace.
static void spin_us(uint32_t us) {
    const uint64_t cps = SYSPAGE_ENTRY(qtime)->cycles_per_sec;
    const uint64_t end = ClockCycles() + (cps * us) / 1000000ULL;
    while (ClockCycles() < end) { }
}

// The calling thread's *current* priority, including any inherited boost.
// (The kill check showed this returns 30 inside a handler for a prio-30 client.)
static int my_priority() {
    sched_param sp{};
    int policy = 0;
    pthread_getschedparam(pthread_self(), &policy, &sp);
    return sp.sched_priority;
}

// The "real work": a checksum the client can verify, so a functional test can
// tell a correct reply from a wrong one. FNV-1a over the id and input bytes.
static uint32_t fnv1a(uint32_t id, uint32_t input) {
    uint32_t h = 2166136261u;
    const uint32_t words[2] = {id, input};
    const unsigned char* p = reinterpret_cast<const unsigned char*>(words);
    for (size_t i = 0; i < sizeof words; ++i) { h ^= p[i]; h *= 16777619u; }
    return h;
}

// ---- server -----------------------------------------------------------------

enum class Mode { Handoff, Inherit, Direct };
static Mode g_mode = Mode::Handoff;

// Do the work for one request and reply. Runs in the worker (handoff) or in the
// receive thread itself (direct). Marker 102 records the priority it ran at.
static void serve(int rcvid, const Request& req) {
    spin_us(req.work_us);
    Reply r{req.id, 0, fnv1a(req.id, req.input)};
    mark(EV_SRV_REPLY, req.id, my_priority());
    MsgReply(rcvid, EOK, &r, sizeof r);    // unblocks the client
}

// Handoff queue: a bounded ring protected by a mutex, with a condvar to wake
// the worker. This is the defect: pthread_cond_signal() makes the worker READY
// at the worker's OWN priority. The client's priority, which the kernel gave to
// the receive thread along with the message, does not travel with the request.
// (QNX mutexes do inherit priority by default, but the worker only holds this
// one for a few instructions, so that boost is too short to hide the defect.)
struct Item { int rcvid; Request req; int client_prio; };

static const unsigned kQueueCap = 64;
static pthread_mutex_t g_qmtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_qcv  = PTHREAD_COND_INITIALIZER;
static pthread_t       g_worker;
// Guarded by g_qmtx:
static Item     g_items[kQueueCap];
static unsigned g_head = 0, g_count = 0;
static int      g_active_prio = 0;   // client priority of the item being served, 0 = idle

// Inherit mode: the priority the worker needs right now. That is the highest of
// the request it is serving, every queued request, and its own base priority.
// Call with g_qmtx held.
static int worker_target_prio_locked() {
    int p = std::max(kWorkerPrio, g_active_prio);
    for (unsigned i = 0; i < g_count; ++i)
        p = std::max(p, g_items[(g_head + i) % kQueueCap].client_prio);
    return p;
}

static void set_prio(pthread_t thr, int prio) {
    int rc = pthread_setschedprio(thr, prio);
    if (rc != EOK) fprintf(stderr, "pthread_setschedprio(%d): %s\n", prio, strerror(rc));
}

static void* worker_main(void*) {
    pin_self();
    pthread_setname_np(pthread_self(), "rl_worker");
    for (;;) {
        pthread_mutex_lock(&g_qmtx);
        while (g_count == 0) pthread_cond_wait(&g_qcv, &g_qmtx);
        Item it = g_items[g_head];
        g_head = (g_head + 1) % kQueueCap;
        --g_count;
        g_active_prio = it.client_prio;
        pthread_mutex_unlock(&g_qmtx);

        serve(it.rcvid, it.req);

        if (g_mode == Mode::Inherit) {
            // Drop the boost now that the reply is sent, so no post-reply work runs
            // at the client's priority (rule 3). Do it under the mutex. On SMP the
            // client may already have sent its next request on another core, and
            // the receive thread may have raised us again for it. Recomputing from
            // the queue keeps that boost instead of wiping it out.
            pthread_mutex_lock(&g_qmtx);
            g_active_prio = 0;
            set_prio(pthread_self(), worker_target_prio_locked());
            pthread_mutex_unlock(&g_qmtx);
        }
    }
    return nullptr;
}

static int start_worker() {
    // Explicit scheduling: without it the worker would copy the creating
    // thread's priority, which depends on how the server was started.
    pthread_attr_t a;
    pthread_attr_init(&a);
    pthread_attr_setinheritsched(&a, PTHREAD_EXPLICIT_SCHED);
    pthread_attr_setschedpolicy(&a, SCHED_RR);
    sched_param sp{};
    sp.sched_priority = kWorkerPrio;
    pthread_attr_setschedparam(&a, &sp);
    int rc = pthread_create(&g_worker, &a, worker_main, nullptr);
    pthread_attr_destroy(&a);
    if (rc != EOK) { fprintf(stderr, "pthread_create: %s\n", strerror(rc)); return -1; }
    return 0;
}

static int run_server(Mode mode) {
    g_mode = mode;
    pin_self();
    // A new process copies its parent's priority. Set the base explicitly, so the
    // scenario doesn't depend on the shell (e.g. one started with `on -p 40`).
    set_prio(pthread_self(), kServerBasePrio);
    name_attach_t* att = name_attach(nullptr, kName, 0);
    if (!att) { perror("name_attach"); return 1; }
    pthread_setname_np(pthread_self(), "rl_recv");
    if (mode != Mode::Direct && start_worker() != 0) return 1;
    const char* mname = mode == Mode::Handoff ? "handoff" : mode == Mode::Inherit ? "inherit" : "direct";
    printf("server: pid %d priority %d, mode %s, listening as '%s'%s\n", getpid(), my_priority(),
           mname, kName, g_cpu >= 0 ? " (pinned)" : "");
    fflush(stdout);

    RecvBuf msg;
    for (;;) {
        _msg_info info;
        // RECEIVE-blocked until a message arrives. Delivery makes this thread
        // READY at the SENDER's priority (QNX priority inheritance).
        int rcvid = MsgReceive(att->chid, &msg, sizeof msg, &info);
        if (rcvid == -1) { perror("MsgReceive"); break; }
        if (rcvid == 0) {                                    // a pulse, not a message
            if (msg.pulse.code == _PULSE_CODE_DISCONNECT) ConnectDetach(msg.pulse.scoid);
            continue;
        }
        if (msg.type == _IO_CONNECT) { MsgReply(rcvid, EOK, nullptr, 0); continue; }  // name_open()
        if (msg.type != kMsgType) { MsgError(rcvid, ENOSYS); continue; }
        if (info.msglen < (ssize_t)sizeof(Request)) { MsgError(rcvid, EINVAL); continue; }

        mark(EV_SRV_GOT, msg.req.id, my_priority());

        if (mode == Mode::Direct) {
            // Idiomatic QNX: the work stays on the message path, in the thread
            // that already runs at the client's priority. No priority code needed.
            // Trade-off: one receive thread serializes all clients (rule 2 territory).
            serve(rcvid, msg.req);
            continue;
        }

        pthread_mutex_lock(&g_qmtx);
        bool queued = g_count < kQueueCap;
        if (queued) {
            g_items[(g_head + g_count) % kQueueCap] = Item{rcvid, msg.req, info.priority};
            ++g_count;
            if (mode == Mode::Inherit) {
                // The fix: carry the client's priority across the handoff by hand.
                // It has to happen HERE, in the receive thread. That thread already
                // runs at the client's priority. A prio-10 worker under a prio-20
                // hog could never get a CPU to raise itself.
                set_prio(g_worker, worker_target_prio_locked());
            }
            pthread_cond_signal(&g_qcv);
        }
        pthread_mutex_unlock(&g_qmtx);
        if (!queued) MsgError(rcvid, EAGAIN);                // overflow is visible to the client
    }
    name_detach(att, 0);
    return 0;
}

// ---- client -----------------------------------------------------------------

static uint64_t mono_ns() {
    timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

// Timers normally expire on the 1 ms clock tick. The aligned capture
// (2026-11-13) showed timer interrupts at exact multiples of 1000 us, and each
// run's "release delay" was a constant 38-815 us: tick quantization, not
// waiting. TIMER_PRECISE asks for a high-resolution timer instead. Capture 3
// (2026-11-14) showed that it is ACCEPTED here but changes nothing measurable:
// wakeups still trail the scheduled time by a constant few hundred us. The
// analyzer doesn't depend on it, because it takes each release from the kernel
// (the moment the timer actually woke the client). If the flag is rejected, fall
// back to plain absolute sleeps (once, with a message).
static std::atomic<bool> g_precise{true};

static void sleep_until_ns(uint64_t t) {
    timespec ts{(time_t)(t / 1000000000ULL), (long)(t % 1000000000ULL)};
    if (g_precise) {
        int rc = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME | TIMER_PRECISE, &ts, nullptr);
        if (rc != EINVAL) return;                  // clock_nanosleep returns the error number
        if (g_precise.exchange(false))
            fprintf(stderr, "clock_nanosleep: TIMER_PRECISE rejected, using tick timing\n");
    }
    clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, nullptr);
}

static int run_client(uint32_t index, uint32_t count, uint32_t work_us, uint32_t period_ms,
                      uint32_t deadline_us) {
    pin_self();
    int coid = name_open(kName, 0);
    if (coid == -1) { perror("name_open"); return 1; }
    pthread_setname_np(pthread_self(), "rl_client");

    const double cps = (double)SYSPAGE_ENTRY(qtime)->cycles_per_sec;
    printf("client %u: pid %d priority %d, %u requests, work %u us, period %u ms (fixed rate), "
           "deadline %u us\n", index, getpid(), my_priority(), count, work_us, period_ms, deadline_us);

    // Requests are released on a fixed schedule (every period_ms), like a real
    // periodic task. The first version slept period_ms AFTER each reply. Under
    // the hog that let the server's delay set the schedule, and the client
    // fell into step with the hog's cycle: every request hit the same phase
    // (untraced run, 2026-11-13). A release that is already past when the
    // previous request returns is skipped, not sent late in a burst.
    const uint64_t period_ns = (uint64_t)period_ms * 1000000ULL;
    uint64_t release = mono_ns();
    uint32_t skipped = 0;

    // Per-request results are kept in memory and printed after the loop. Printing
    // inside the loop wrote to the log file on the SD card, and once a write
    // REPLY-blocked the client in devb-sdmmc for 163 ms (28 releases skipped in
    // the aligned 'fixed' capture). No file I/O while measuring.
    struct Rec { uint32_t seq; double us; bool late, ok; int err; };
    std::vector<Rec> recs;
    recs.reserve(count);
    std::vector<double> lat, rel;
    lat.reserve(count);
    rel.reserve(count);
    uint32_t correct = 0, late = 0;
    for (uint32_t seq = 1; seq <= count; ++seq) {
        const uint32_t id    = (index << 24) | seq;
        const uint32_t input = id * 2654435761u;         // varies per request
        Request req{kMsgType, 0, id, work_us, input};
        Reply   rep{};

        // Release delay: how long after its scheduled release this request is
        // actually sent. It is ~0 when the client outranks the load. When the load
        // is at the client's own priority, the client itself can wait here. That
        // wait comes before marker 100, so neither the latency below nor the
        // trace's request interval includes it.
        rel.push_back((double)(mono_ns() - release) / 1000.0);
        mark(EV_REQ_START, id, (int)deadline_us);
        uint64_t t0 = ClockCycles();
        // SEND-blocked until the server receives, then REPLY-blocked until it replies.
        int rc = MsgSend(coid, &req, sizeof req, &rep, sizeof rep);
        uint64_t t1 = ClockCycles();
        int err = (rc == -1) ? errno : 0;
        bool ok = rc != -1 && rep.id == id && rep.result == fnv1a(id, input);
        mark(EV_REQ_END, id, ok ? 1 : 2);

        double us = (double)(t1 - t0) * 1e6 / cps;
        bool is_late = deadline_us != 0 && us > deadline_us;
        lat.push_back(us);
        correct += ok;
        late += is_late;
        recs.push_back(Rec{seq, us, is_late, ok, err});
        release += period_ns;
        const uint64_t now = mono_ns();
        while (release <= now) { release += period_ns; ++skipped; }   // overran: skip
        sleep_until_ns(release);
    }
    name_close(coid);

    for (const Rec& r : recs)
        printf("req %u:%-4u %9.1f us%s%s%s%s\n", index, r.seq, r.us, r.late ? "  LATE" : "",
               r.ok ? "" : "  WRONG", r.err ? "  " : "", r.err ? strerror(r.err) : "");
    std::sort(lat.begin(), lat.end());
    printf("timers: %s\n", g_precise ? "TIMER_PRECISE accepted (no effect measured on this image)"
                                     : "TIMER_PRECISE rejected, tick timing");
    printf("releases skipped (previous request overran its period): %u\n", skipped);
    printf("functional: %u/%u correct\n", correct, count);
    printf("deadline %u us: %u/%u late (client-measured)\n", deadline_us, late, count);
    if (!lat.empty())
        printf("latency us: min %.1f  median %.1f  max %.1f\n",
               lat.front(), lat[lat.size() / 2], lat.back());
    std::sort(rel.begin(), rel.end());
    if (!rel.empty())
        printf("release delay us (scheduled release -> send, incl. timer tick rounding): "
               "median %.1f  max %.1f\n",
               rel[rel.size() / 2], rel.back());
    // Exit code = functional result only. Timing is judged separately, on purpose:
    // the point of the demo is a run that passes this and still misses deadlines.
    return correct == count ? 0 : 1;
}

// ---- hog --------------------------------------------------------------------
//
// CPU load at a chosen priority. Two design points:
// - One thread per CPU by default. QNX schedules by strict priority across ALL
//   cores, so to keep a prio-10 thread off the CPU, every core must be busy with
//   something above it. One hog thread on a 4-core Pi leaves 3 cores free.
//   With --cpu everything shares one core, so one hog thread is enough.
// - Duty-cycled (busy, then sleep). A hog that never sleeps would starve the
//   prio-10 worker forever, and requests would hang instead of being late.
// - Aligned: all threads follow ONE absolute schedule. Each cycle starts at
//   start + k*(busy+idle); the thread spins until busy_ms into the cycle, then
//   sleeps until the next cycle starts. So all cores are busy at the same time
//   and free at the same time. The first version slept idle_ms after each busy
//   spell. Its threads drifted apart, a core was almost always free, and the
//   multi-core defect run had only 18/200 late (traced capture, 2026-11-13).
//   --unaligned keeps that old behaviour.
// Spinning reads ClockCycles() (no kernel call, so the spin adds no trace
// events). Sleeping uses CLOCK_MONOTONIC, the clock the timers use.

struct HogArgs {
    int index; uint32_t busy_ms, idle_ms; bool aligned;
    uint64_t start_cyc, start_ns, end_cyc;   // shared schedule, set once by run_hog
};

static void* hog_main(void* p) {
    const HogArgs* a = static_cast<const HogArgs*>(p);
    pin_self();
    char name[16];
    snprintf(name, sizeof name, "rl_hog%d", a->index);
    pthread_setname_np(pthread_self(), name);
    if (!a->aligned) {
        while (ClockCycles() < a->end_cyc) {
            spin_us(a->busy_ms * 1000);
            if (a->idle_ms) delay(a->idle_ms);
        }
        return nullptr;
    }
    const uint64_t cps       = SYSPAGE_ENTRY(qtime)->cycles_per_sec;
    const uint64_t period_ms = a->busy_ms + a->idle_ms;
    for (uint64_t k = 0;; ++k) {
        const uint64_t cycle_cyc = a->start_cyc + k * period_ms * cps / 1000;
        if (cycle_cyc >= a->end_cyc) break;
        const uint64_t busy_end = cycle_cyc + (uint64_t)a->busy_ms * cps / 1000;
        while (ClockCycles() < busy_end) { }
        // A wakeup that comes late (timer tick granularity) only shortens the next
        // busy spell; it can't shift the schedule, because the spell ends at an
        // absolute time.
        sleep_until_ns(a->start_ns + (k + 1) * period_ms * 1000000ULL);
    }
    return nullptr;
}

static int run_hog(int threads, int prio, uint32_t busy_ms, uint32_t idle_ms, uint32_t seconds,
                   bool fifo, bool aligned) {
    pin_self();
    const uint64_t cps = SYSPAGE_ENTRY(qtime)->cycles_per_sec;
    // One shared start, a little in the future so every thread exists before the
    // first cycle. The same instant is read on both clocks.
    const uint64_t lead_ms   = 20;
    const uint64_t start_cyc = ClockCycles() + lead_ms * cps / 1000;
    const uint64_t start_ns  = mono_ns() + lead_ms * 1000000ULL;
    const uint64_t end_cyc   = start_cyc + cps * seconds;   // bounded: the hog always stops
    printf("hog: pid %d, %d thread(s) at priority %d %s, busy %u ms / idle %u ms, %s, for %u s%s\n",
           getpid(), threads, prio, fifo ? "FIFO" : "RR", busy_ms, idle_ms,
           aligned ? "aligned" : "unaligned", seconds, g_cpu >= 0 ? " (pinned)" : "");
    fflush(stdout);

    std::vector<pthread_t> tids(threads);
    std::vector<HogArgs>   args(threads);
    for (int i = 0; i < threads; ++i) {
        args[i] = HogArgs{i, busy_ms, idle_ms, aligned, start_cyc, start_ns, end_cyc};
        pthread_attr_t a;
        pthread_attr_init(&a);
        pthread_attr_setinheritsched(&a, PTHREAD_EXPLICIT_SCHED);
        pthread_attr_setschedpolicy(&a, fifo ? SCHED_FIFO : SCHED_RR);
        sched_param sp{};
        sp.sched_priority = prio;
        pthread_attr_setschedparam(&a, &sp);
        int rc = pthread_create(&tids[i], &a, hog_main, &args[i]);
        pthread_attr_destroy(&a);
        if (rc != EOK) { fprintf(stderr, "pthread_create: %s\n", strerror(rc)); return 1; }
    }
    for (pthread_t t : tids) pthread_join(t, nullptr);
    printf("hog: done\n");
    return 0;
}

// ---- main -------------------------------------------------------------------

static void usage(const char* argv0) {
    fprintf(stderr,
            "usage: %s server handoff|inherit|direct [--cpu N]\n"
            "       %s client [index 0-255] [count] [work_us] [period_ms] [deadline_us] [--cpu N]\n"
            "       %s hog [threads, 0 = auto] [prio] [busy_ms] [idle_ms] [seconds] [--fifo] "
            "[--unaligned] [--cpu N]\n",
            argv0, argv0, argv0);
}

int main(int argc, char** argv) {
    // Pull out the options. What is left is positional: av[0] role av[1...] values.
    std::vector<const char*> av;
    bool fifo = false, aligned = true;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--cpu") == 0 && i + 1 < argc) g_cpu = atoi(argv[++i]);
        else if (strcmp(argv[i], "--fifo") == 0)           fifo = true;
        else if (strcmp(argv[i], "--unaligned") == 0)      aligned = false;
        else                                               av.push_back(argv[i]);
    }
    const int ncpu = _syspage_ptr->num_cpu;
    if (g_cpu >= ncpu) { fprintf(stderr, "--cpu %d: this system has %d CPUs\n", g_cpu, ncpu); return 2; }
    auto arg = [&](size_t i, uint32_t dflt) { return av.size() > i ? (uint32_t)atoi(av[i]) : dflt; };
    const std::string role = av.empty() ? "" : av[0];

    if (role == "server" && av.size() >= 2) {
        const std::string m = av[1];
        if (m == "handoff") return run_server(Mode::Handoff);
        if (m == "inherit") return run_server(Mode::Inherit);
        if (m == "direct")  return run_server(Mode::Direct);
    }
    if (role == "client") {
        uint32_t index = arg(1, 0), count = arg(2, 200);
        if (index > 255 || count == 0 || count >= (1u << 24)) { usage(argv[0]); return 2; }
        return run_client(index, count, arg(3, 500), arg(4, 7), arg(5, 2000));
    }
    if (role == "hog") {
        int threads = (int)arg(1, 0);
        if (threads == 0) threads = g_cpu >= 0 ? 1 : ncpu;   // auto: one per core, or one if pinned
        int prio = (int)arg(2, 20);
        if (threads < 1 || prio < 1 || prio > 255) { usage(argv[0]); return 2; }
        return run_hog(threads, prio, arg(3, 8), arg(4, 2), arg(5, 5), fifo, aligned);
    }
    usage(argv[0]);
    return 2;
}
