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


def scenario(skip=(), d1=30, swap_101_102=False, mid=""):
    """Client on CPU 0, server on CPU 1, one request with id 1.

    skip: marker codes to leave out. swap_101_102: emit 102 at t=30 and 101 at
    t=530, i.e. the server's markers in the wrong order (file stays time-ordered).
    mid: extra line(s) placed between t=30 and t=530, during the server's work.
    """
    first, second = (102, 101) if swap_101_102 else (101, 102)
    lines = [
        th(10, 0, "THRUNNING", *CLIENT, 30),
        th(11, 1, "THRUNNING", 1, 2, 0),                 # idle on CPU 1
        mark(20, 0, 100, 1),
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
        mark(30, 1, first, 1, d1 if first == 101 else 0),
        mid,
        mark(530, 1, second, 1, d1 if second == 101 else 0),
        th(531, 1, "THREADY", *CLIENT, 30),              # server replies: wakes client
        th(532, 0, "THREADY", 1, 1, 0),
        th(533, 0, "THRUNNING", *CLIENT, 30),
        th(534, 1, "THRECEIVE", *SERVER, 30),
        mark(540, 0, 103, 1),
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
        # reply_us, total_us and the 103 cpu print as '-'
        self.assertEqual(out.splitlines()[-1].split()[-5:], ["-", "-", "0,1,1,-", "cut", "off"])
        # Last event is THRECEIVE at t=534, last marker 102 at t=530: 4 ticks = 4 us.
        self.assertIn("note: req 1: cut off at trace end (missing 103); "
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
        self.assertTrue(warned(res, "req 1: missing marker(s) 101, 102, 103 (client 100/1@30 "
                                    f"started request 2 later (line {line_of(text, req2)}))"),
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
