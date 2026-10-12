"""The Pro DJ Link replayer: reading a recording, merging interfaces, and
sending at the recorded timing.

    python3 -m unittest discover -s tests      (or: make test)
"""
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "tools"))
from djlink_replay import RECORDINGS, merge, packets, play  # noqa: E402

RECORDING = (RECORDINGS / "two-decks-2026-10-08-en0.pcap").read_bytes()


class Replay(unittest.TestCase):
    def test_a_recording_reads_as_pro_dj_link_in_time_order_from_both_decks(self):
        list_ = merge([packets(RECORDING)])
        self.assertEqual(sorted({port for _, port, _ in list_}), [50000, 50001, 50002])
        self.assertTrue(all(a[0] <= b[0] for a, b in zip(list_, list_[1:])), "in time order")
        self.assertEqual(sorted({p[0x21] for _, port, p in list_ if port == 50001}), [1, 3], "players 1 and 3 beating")
        self.assertGreater(list_[-1][0] - list_[0][0], 10, "more than ten seconds")

    def test_the_same_packet_on_two_links_plays_once_and_our_announcements_not_at_all(self):
        one = packets(RECORDING)
        twice = merge([one, [(t + 0.002, port, p) for t, port, p in one]])
        self.assertEqual(len(twice), len(merge([one])), "the second link's copies dropped")
        theirs = next(p for _, port, p in one if port == 50000)
        ours = theirs[:12] + b"sequent\0" + theirs[20:]
        self.assertEqual(merge([[(0.0, 50000, ours)]]), [], "the bridge's own player left out")
        with self.assertRaisesRegex(ValueError, "not a pcap"):
            packets(bytes(40))

    def test_played_at_the_recorded_timing_on_moved_ports(self):
        # A pretend clock that sleeping moves on, and every reading nudges a
        # tenth of a millisecond, as time passes while play() waits out the
        # last moment before each packet.
        now = [0.0]

        def clock():
            now[0] += 0.0001
            return now[0]
        sent = []
        list_ = [(10.0, 50000, b"a"), (10.5, 50001, b"b"), (12.0, 50002, b"c")]
        play(list_, speed=2, offset=1000, send=lambda port, p: sent.append((now[0], port, p)),
             clock=clock, sleep=lambda s: now.__setitem__(0, now[0] + s))
        self.assertEqual([(port, p) for _, port, p in sent], [(51000, b"a"), (51001, b"b"), (51002, b"c")])
        start = sent[0][0]
        for (t, _, _), due in zip(sent, (0.0, 0.25, 1.0)):
            self.assertAlmostEqual(t - start, due, delta=0.001)


if __name__ == "__main__":
    unittest.main()
