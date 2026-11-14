"""Tests for rl_analyze.py.   Run:  python -m unittest discover -s host\\analyzer -v

Two kinds of test:
- Regression: the real kill-check trace (Pi 5, 2026-11-10). The expected values
  are the measured request-1 numbers recorded in CLAUDE.md and the trace's NOTES.md.
- Synthetic: a few hand-written trace lines in the real traceprinter format, used
  only to exercise parser logic. They are NOT measurements.
"""
import io
import os
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rl_analyze as rl  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
PROBE = REPO / "traces" / "2026-11-10-killcheck" / "probe.txt"


@unittest.skipUnless(PROBE.exists(),
                     f"{PROBE} missing (traces/**/*.txt is gitignored). Regenerate it from "
                     f"probe.kev with traceprinter -f probe.kev > probe.txt (Pi or host "
                     f"traceprinter.exe; see CLAUDE.md gotchas)")
class KillCheckRegression(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(PROBE, encoding="utf-8", errors="replace") as f:
            cls.res = rl.analyze(f, str(PROBE))

    def test_header_and_counts(self):
        self.assertEqual(self.res.cps, 54_000_000)
        self.assertEqual(self.res.n_markers, 80)
        self.assertEqual([r.rid for r in self.res.rows], list(range(1, 21)))
        self.assertEqual(self.res.warnings, [])
        self.assertEqual(self.res.notes, [])
        self.assertEqual({r.status for r in self.res.rows}, {"ok"})
        # ipc_probe reports no deadline and no reply check: d1 = 0 on 100 and 103.
        self.assertEqual({(r.deadline_us, r.late) for r in self.res.rows}, {(None, None)})
        self.assertEqual(self.res.rows[0].label, "0:1")

    def test_request1_regression_values(self):
        r = self.res.rows[0]
        # Exact ticks at 54 MHz.
        self.assertEqual((r.recv, r.work, r.reply, r.total), (644, 27058, 235, 27937))
        # The values recorded in CLAUDE.md, at 0.1 us resolution.
        got = [rl.fmt_us(x, self.res.cps) for x in (r.recv, r.work, r.reply, r.total)]
        self.assertEqual(got, ["11.9", "501.1", "4.4", "517.4"])

    def test_request1_priority_inheritance(self):
        r = self.res.rows[0]
        self.assertEqual(r.thread(rl.SRV_GOT).prio, 30)   # kernel THRUNNING priority
        self.assertEqual(r.m[rl.SRV_GOT].d1, 30)          # server's self-report
        self.assertEqual(r.thread(rl.REQ_START).prio, 30)

    def test_every_request_same_client_and_server(self):
        clients = {(r.thread(rl.REQ_START).pid, r.thread(rl.REQ_END).pid) for r in self.res.rows}
        servers = {(r.thread(rl.SRV_GOT).pid, r.thread(rl.SRV_REPLY).pid) for r in self.res.rows}
        self.assertEqual(clients, {(13082679, 13082679)})
        self.assertEqual(servers, {(13058101, 13058101)})


# ---- synthetic input (not measurements) ------------------------------------

HEADER = """TRACEPRINTER version 1.02
 -- HEADER FILE INFORMATION --
  TRACE_CYCLES_PER_SEC:: 1000000
         TRACE_CPU_NUM:: 2
 -- KERNEL EVENTS --
"""  # 1 MHz: 1 tick = 1 us, so expected values read directly


def ev(t, cpu, cls, name, rest=""):
    return f"t:0x{t:x} CPU:{cpu:02d} {cls:<15} :{name:<18} {rest}\n"


def th(t, cpu, state, pid, tid, prio):
    return ev(t, cpu, "THREAD", state, f"pid:{pid} tid:{tid} priority:{prio} policy:2")


def mark(t, cpu, code, rid, d1=0):
    return ev(t, cpu, "USREVENT", f"EVENT:{code}", f", d0:0x{rid:08x} d1:0x{d1:08x}")


def time_ev(t, cpu=0):
    """CONTROL TIME: the kernel's record of the counter's high 32 bits."""
    return ev(t, cpu, "CONTROL", "TIME", f"msb:0x{t >> 32:08x} lsb(offset):0x{t & 0xFFFFFFFF:08x}")


START = HEADER + time_ev(0)   # real traces begin with a CONTROL TIME event


def shift(text, base, host32=False):
    """Move every event later by `base` ticks (TIME fields included).

    host32=True prints t: as only its low 32 bits, like the host traceprinter.exe.
    """
    def one(line):
        m = re.match(r"t:0x([0-9a-f]+) (.*)$", line, re.S)
        if not m:
            return line
        t, rest = base + int(m[1], 16), m[2]
        if ":TIME" in rest:
            rest = re.sub(r"msb:0x\w+ lsb\(offset\):0x\w+",
                          f"msb:0x{t >> 32:08x} lsb(offset):0x{t & 0xFFFFFFFF:08x}", rest)
        return f"t:0x{t & 0xFFFFFFFF if host32 else t:x} {rest}"
    return "".join(one(ln) for ln in text.splitlines(keepends=True))


CLIENT, SERVER = (100, 1), (200, 1)


def scenario(skip=(), d1=30, swap_101_102=False, mid="", deadline=0, reply_flag=0, d1_102=0,
             sleep=False):
    """Client on CPU 0, server on CPU 1, one request with id 1.

    skip: marker codes to leave out. swap_101_102: emit 102 at t=30 and 101 at
    t=530, i.e. the server's markers in the wrong order (file stays time-ordered).
    mid: extra line(s) placed between t=30 and t=530, during the server's work.
    deadline / reply_flag / d1_102: d1 of markers 100 / 103 / 102 (0 = not reported).
    sleep: the client sleeps first, and its timer fires at t=6 (THNANOSLEEP ->
    THREADY on CPU 1), so the request's release is t=6. Marker 100 is at t=20.
    """
    first, second = (102, 101) if swap_101_102 else (101, 102)
    d1_of = {101: d1, 102: d1_102}
    pre = [th(3, 0, "THNANOSLEEP", *CLIENT, 30), th(6, 1, "THREADY", *CLIENT, 30)] if sleep else []
    lines = pre + [
        th(10, 0, "THRUNNING", *CLIENT, 30),
        th(11, 1, "THRUNNING", 1, 2, 0),                 # idle on CPU 1
        mark(20, 0, 100, 1, deadline),
        ev(21, 0, "KER_CALL", "MSG_SENDV/11"),
        "                      coid:0x40000001\n",         # continuation line
        "                 info->pid:999\n",                # continuation line
        "\n",
        th(22, 0, "THREADY", *SERVER, 30),               # CPU 0 wakes the server
        th(23, 1, "THREADY", 1, 2, 0),                   # idle leaves CPU 1
        th(24, 1, "THRUNNING", *SERVER, 30),             # server dispatched on CPU 1
        th(25, 0, "THREPLY", *CLIENT, 30),               # client blocks on CPU 0
        th(26, 0, "THRUNNING", 1, 1, 0),                 # idle on CPU 0
        th(29, 1, "THREADY", 300, 1, 10),                # another thread's THREADY on CPU 1
        mark(30, 1, first, 1, d1_of[first]),
        mid,
        mark(530, 1, second, 1, d1_of[second]),
        th(531, 1, "THREADY", *CLIENT, 30),              # server replies: wakes client
        th(532, 0, "THREADY", 1, 1, 0),
        th(533, 0, "THRUNNING", *CLIENT, 30),
        th(534, 1, "THRECEIVE", *SERVER, 30),
        mark(540, 0, 103, 1, reply_flag),
    ]
    lines = [ln for ln in lines if not any(f":EVENT:{c} " in ln for c in skip)]
    return START + time_ev(0, 1) + "".join(lines)


def run(text):
    return rl.analyze(io.StringIO(text), "<synthetic>")


class SyntheticParser(unittest.TestCase):
    def test_cross_cpu_request(self):
        res = run(scenario())
        self.assertEqual(res.warnings, [])
        r = res.rows[0]
        self.assertEqual((r.recv, r.work, r.reply, r.total), (10, 500, 10, 520))
        self.assertEqual(r.thread(rl.REQ_START), rl.Thread(*CLIENT, 30))
        self.assertEqual(r.thread(rl.REQ_END), rl.Thread(*CLIENT, 30))
        self.assertEqual(r.thread(rl.SRV_GOT), rl.Thread(*SERVER, 30))
        # Marker 102 comes after a THREADY for pid 300 on CPU 1; still the server's.
        self.assertEqual(r.thread(rl.SRV_REPLY), rl.Thread(*SERVER, 30))
        self.assertEqual([r.m[c].cpu for c in rl.MARKER_CODES], [0, 1, 1, 0])

    def test_line_numbers_count_header(self):
        res = run(scenario())
        text_lines = scenario().splitlines()
        mk = res.rows[0].m[rl.REQ_START]
        self.assertIn("EVENT:100", text_lines[mk.lineno - 1])

    def test_out_of_order_warns(self):
        res = run(scenario(swap_101_102=True))
        self.assertTrue(any("out of order" in w for w in res.warnings), res.warnings)

    def test_priority_mismatch_warns(self):
        res = run(scenario(d1=10))
        self.assertTrue(any("self-reported priority 10" in w for w in res.warnings), res.warnings)

    def test_marker_before_any_thrunning_is_unknown(self):
        res = run(START + mark(5, 0, 100, 7))
        self.assertIsNone(res.rows[0].thread(rl.REQ_START))
        self.assertTrue(any("unknown emitter" in w for w in res.warnings), res.warnings)

    def test_marker_after_thread_left_cpu_is_unknown(self):
        text = START + th(10, 0, "THRUNNING", *CLIENT, 30) + th(11, 0, "THREPLY", *CLIENT, 30) \
               + mark(12, 0, 100, 1)
        res = run(text)
        self.assertIsNone(res.rows[0].thread(rl.REQ_START))

    def test_32bit_timestamps_without_time_event_warn(self):
        res = run(HEADER + th(10, 0, "THRUNNING", *CLIENT, 30) + mark(12, 0, 100, 1))
        self.assertTrue(any("msb assumed 0" in w for w in res.warnings), res.warnings)

    def test_missing_cycles_per_sec_is_fatal(self):
        with self.assertRaises(rl.TraceError):
            run(" -- KERNEL EVENTS -- \n" + mark(5, 0, 100, 1))


def run_main(text):
    """Run the CLI on `text`; returns (exit code, stdout, stderr)."""
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "t.txt")
        with open(p, "w", encoding="utf-8") as f:
            f.write(text)
        with redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()) as err:
            code = rl.main([p])
    return code, out.getvalue(), err.getvalue()


def warned(res, text):
    return any(text in w for w in res.warnings)


def line_of(text, line):
    """1-based line number of `line` in `text` (computed, not counted by hand)."""
    return text.splitlines().index(line.rstrip("\n")) + 1


class SyntheticCutOff(unittest.TestCase):
    """Missing markers: the capture ended (note, exit 0) vs markers lost (warning, exit 1)."""

    def test_last_request_cut_off_is_a_note_not_a_warning(self):
        text = scenario(skip=(103,))     # trace stops while the client waits for its reply
        res = run(text)
        self.assertEqual(res.warnings, [])
        self.assertEqual(res.rows[0].status, "cut off")
        self.assertIsNone(res.rows[0].total)
        code, out, err = run_main(text)
        self.assertEqual(code, 0)
        # reply_us, send_us, resp_us, ddl_us and late print as '-'
        self.assertEqual(out.splitlines()[-1].split()[-7:], ["-", "-", "-", "-", "-", "cut", "off"])
        # Last event is THRECEIVE at t=534, last marker 102 at t=530: 4 ticks = 4 us.
        self.assertIn("note: req 0:1: cut off at trace end (missing 103); "
                      "the capture ended 4.0 us after marker 102", err)

    def test_cut_off_right_after_start(self):
        res = run(scenario(skip=(101, 102, 103)))
        self.assertEqual((res.warnings, res.rows[0].status), ([], "cut off"))

    def test_later_request_from_same_client_means_markers_were_lost(self):
        # MsgSend blocks, so request 2 can only start after request 1 got its reply.
        req2 = mark(30, 0, 100, 2)
        text = START + th(10, 0, "THRUNNING", *CLIENT, 30) + mark(20, 0, 100, 1) + req2
        res = run(text)
        r1, r2 = res.rows
        self.assertEqual((r1.status, r2.status), ("incomplete", "cut off"))
        self.assertTrue(warned(res, "req 0:1: missing marker(s) 101, 102, 103 (client 100/1@30 "
                                    f"started request 0:2 later (line {line_of(text, req2)}))"),
                        res.warnings)
        self.assertEqual(run_main(text)[0], 1)

    def test_client_died_is_not_cut_off(self):
        death = ev(30, 0, "THREAD", "THDESTROY", "pid:100 tid:1")   # no priority field, as on the Pi
        text = START + th(10, 0, "THRUNNING", *CLIENT, 30) + mark(20, 0, 100, 1) + death
        res = run(text)
        self.assertEqual(res.rows[0].status, "incomplete")
        self.assertTrue(warned(res, f"client 100/1@30 died at line {line_of(text, death)}"),
                        res.warnings)

    def test_gap_in_the_middle_is_not_cut_off(self):
        res = run(scenario(skip=(101,)))
        self.assertEqual(res.rows[0].status, "incomplete")
        self.assertTrue(warned(res, "missing marker(s) 101 (markers missing before later ones)"),
                        res.warnings)

    def test_no_start_marker_is_not_cut_off(self):
        res = run(scenario(skip=(100,)))
        self.assertEqual(res.rows[0].status, "incomplete")
        self.assertTrue(warned(res, "no start marker"), res.warnings)

    def test_other_warning_gives_status_check(self):
        self.assertEqual(run(scenario(d1=10)).rows[0].status, "check")


class SyntheticEmpty(unittest.TestCase):
    def test_no_events_recognised_warns_and_exit_1(self):
        text = scenario().replace(" CPU:", "  CPU:")   # a layout the event regex rejects
        res = run(text)
        self.assertEqual((res.n_events, res.rows), (0, []))
        self.assertTrue(warned(res, "no trace events recognised"), res.warnings)
        self.assertEqual(run_main(text)[0], 1)

    def test_events_but_no_probe_markers_warns(self):
        text = START + th(10, 0, "THRUNNING", *CLIENT, 30) + mark(20, 0, 7, 1)   # foreign code 7
        res = run(text)
        self.assertEqual((res.n_markers, res.rows), (0, []))
        self.assertTrue(warned(res, "no ipc_probe markers (user events 100-103) found"),
                        res.warnings)
        self.assertEqual(run_main(text)[0], 1)


CLIENT_B, WORKER = (101, 1), (200, 2)
ID_B1 = (1 << 24) | 1          # client index 1, sequence 1


def two_clients(id_b):
    """Clients A (CPU 0) and B (CPU 1) each send one request to server 200/1 on
    CPU 2, both in flight at once. A uses id 1, B uses id_b."""
    return (START + th(10, 0, "THRUNNING", *CLIENT, 30) + th(11, 1, "THRUNNING", *CLIENT_B, 30)
            + th(12, 2, "THRUNNING", *SERVER, 30)
            + mark(20, 0, 100, 1) + mark(21, 1, 100, id_b)
            + mark(30, 2, 101, 1, 30) + mark(530, 2, 102, 1) + mark(540, 0, 103, 1)
            + mark(541, 2, 101, id_b, 30) + mark(1041, 2, 102, id_b) + mark(1050, 1, 103, id_b))


class SyntheticKeys(unittest.TestCase):
    """Requests keyed by (client thread, request id); server markers matched by in-flight id."""

    def test_two_clients_with_distinct_ids(self):
        res = run(two_clients(ID_B1))
        self.assertEqual(res.warnings, [])
        a, b = res.rows
        self.assertEqual((a.label, a.client, b.label, b.client), ("0:1", CLIENT, "1:1", CLIENT_B))
        self.assertEqual((a.recv, a.work, b.recv, b.work), (10, 500, 520, 500))

    def test_same_id_in_flight_from_two_clients_is_a_collision(self):
        res = run(two_clients(1))          # the "two clients both number from 1" case
        self.assertEqual(sum("request id collision" in w for w in res.warnings), 2, res.warnings)
        self.assertEqual({r.client for r in res.rows}, {CLIENT, CLIENT_B})
        self.assertTrue(all(r.status == "check" for r in res.rows))

    def test_handoff_inside_the_server_is_not_a_warning(self):
        text = (START + th(10, 0, "THRUNNING", *CLIENT, 30) + th(12, 2, "THRUNNING", *SERVER, 30)
                + mark(20, 0, 100, 1) + mark(30, 2, 101, 1, 30)
                + th(40, 3, "THRUNNING", *WORKER, 10) + mark(540, 3, 102, 1, 10)
                + mark(550, 0, 103, 1))
        res = run(text)
        self.assertEqual(res.warnings, [])
        self.assertEqual(res.rows[0].thread(rl.SRV_REPLY), rl.Thread(*WORKER, 10))
        out = io.StringIO()
        rl.print_table(res, out)
        self.assertIn(" /2@10 ", out.getvalue())   # replier column: worker of the same process

    def test_server_markers_from_two_processes_warn(self):
        text = (START + th(10, 0, "THRUNNING", *CLIENT, 30) + th(12, 2, "THRUNNING", *SERVER, 30)
                + mark(20, 0, 100, 1) + mark(30, 2, 101, 1, 30)
                + th(40, 3, "THRUNNING", 300, 1, 30) + mark(540, 3, 102, 1)
                + mark(550, 0, 103, 1))
        self.assertTrue(warned(run(text), "server process differs"))


class SyntheticDeadline(unittest.TestCase):
    """Verdict on resp (release -> reply); send (100 -> 103) shown alongside."""

    def test_release_comes_from_the_kernel_wake(self):
        r = run(scenario(sleep=True)).rows[0]
        # Timer fired at t=6, marker 100 at 20, 103 at 540 (1 tick = 1 us here).
        self.assertEqual((r.release, r.wait, r.total, r.resp), (6, 14, 520, 534))

    def test_late_from_release_even_when_on_time_from_send(self):
        res = run(scenario(sleep=True, deadline=525))   # send 520 <= 525 < resp 534
        r = res.rows[0]
        self.assertEqual((r.late, r.judged_from), (True, "release"))
        self.assertEqual(res.warnings, [])              # lateness is a verdict, not a warning
        out = io.StringIO()
        rl.print_table(res, out)
        self.assertIn("deadline: 1/1 late, judged on resp", out.getvalue())

    def test_no_release_in_trace_falls_back_to_send(self):
        res = run(scenario(deadline=515))               # no sleep before the request
        r = res.rows[0]
        self.assertEqual((r.release, r.late, r.judged_from), (None, True, "send"))
        out = io.StringIO()
        rl.print_table(res, out)
        self.assertIn(" LATE* ", out.getvalue())
        self.assertIn("1 marked * judged on send", out.getvalue())

    def test_a_wake_only_counts_for_the_next_request(self):
        text = (START + th(3, 0, "THNANOSLEEP", *CLIENT, 30) + th(6, 0, "THREADY", *CLIENT, 30)
                + th(10, 0, "THRUNNING", *CLIENT, 30)
                + mark(20, 0, 100, 1, 100) + mark(30, 0, 103, 1)
                + mark(40, 0, 100, 2, 100) + mark(50, 0, 103, 2))   # no sleep before request 2
        r1, r2 = run(text).rows
        self.assertEqual((r1.release, r2.release), (6, None))

    def test_no_deadline_no_verdict(self):
        r = run(scenario(sleep=True)).rows[0]
        self.assertEqual((r.deadline_us, r.late), (None, None))

    def test_wrong_reply_is_a_functional_failure(self):
        text = scenario(reply_flag=2)
        res = run(text)
        self.assertEqual(res.rows[0].status, "wrong reply")
        self.assertTrue(warned(res, "wrong reply"))
        code, out, _ = run_main(text)
        self.assertEqual(code, 1)
        self.assertIn("replies: 0 correct, 1 wrong", out)

    def test_correct_reply_is_counted(self):
        res = run(scenario(reply_flag=1))
        self.assertEqual(res.warnings, [])
        out = io.StringIO()
        rl.print_table(res, out)
        self.assertIn("replies: 1 correct, 0 wrong", out.getvalue())

    def test_replying_thread_priority_cross_check(self):
        res = run(scenario(d1_102=10))                  # kernel ran the replier at 30
        self.assertTrue(warned(res, "replying thread self-reported priority 10"), res.warnings)


# The counter's low 32 bits wrap at rel. tick 256 (0xFFFFFF00 + 0x100): after
# marker 101 (t=30) and before 102 (t=530), i.e. in the middle of the server's work.
WRAP_BASE = (0x38 << 32) | 0xFFFFFF00


class SyntheticWrap(unittest.TestCase):
    def test_request_across_32bit_wrap_host_format(self):
        text = shift(scenario(), WRAP_BASE, host32=True)
        # The input really is wrapped: 102 is printed with a smaller t than 101.
        self.assertRegex(text, r"(?m)^t:0xffffff1e CPU:01 USREVENT\s+:EVENT:101 ")
        self.assertRegex(text, r"(?m)^t:0x112 CPU:01 USREVENT\s+:EVENT:102 ")
        res = run(text)
        self.assertEqual(res.warnings, [])
        self.assertEqual(res.n_wraps, 1)          # found by wrap detection: no TIME after it
        r = res.rows[0]
        self.assertEqual((r.recv, r.work, r.reply, r.total), (10, 500, 10, 520))
        self.assertEqual(r.m[rl.SRV_GOT].t, 0x38_FFFFFF1E)
        self.assertEqual(r.m[rl.SRV_REPLY].t, 0x39_00000112)

    def test_host_and_full64_formats_agree(self):
        host = run(shift(scenario(), WRAP_BASE, host32=True))
        full = run(shift(scenario(), WRAP_BASE, host32=False))
        self.assertEqual(full.warnings, [])
        self.assertEqual(full.n_wraps, 0)         # full values: nothing to infer
        self.assertEqual(host.rows, full.rows)

    def test_time_event_after_wrap_confirms_msb(self):
        res = run(shift(scenario(mid=time_ev(300, 1)), WRAP_BASE, host32=True))
        self.assertEqual(res.warnings, [])
        self.assertEqual(res.n_wraps, 0)          # the kernel's TIME event told us first
        self.assertEqual(res.rows[0].work, 500)

    def test_contradicting_time_event_warns(self):
        text = shift(scenario(mid=time_ev(300, 1)), WRAP_BASE, host32=True)
        self.assertEqual(text.count("msb:0x00000039"), 1)
        res = run(text.replace("msb:0x00000039", "msb:0x00000038"))
        self.assertTrue(any("CONTROL TIME says" in w for w in res.warnings), res.warnings)


if __name__ == "__main__":
    unittest.main()
