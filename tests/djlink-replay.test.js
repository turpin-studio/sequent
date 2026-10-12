// The Pro DJ Link replayer: reading a recording, merging interfaces.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { packets, merge } from "../tools/djlink-replay.mjs";

const recording = readFileSync(new URL("../tools/recordings/two-decks-2026-10-08-en0.pcap", import.meta.url));

test("a recording reads as Pro DJ Link packets in time order, from both decks", () => {
  const list = merge([packets(recording)]);
  const ports = new Set(list.map(p => p.port));
  assert.deepEqual([...ports].sort(), [50000, 50001, 50002]);
  assert.ok(list.every((p, i) => !i || p.t >= list[i - 1].t), "in time order");
  assert.deepEqual([...new Set(list.filter(p => p.port === 50001).map(p => p.payload[0x21]))].sort(), [1, 3], "players 1 and 3 beating");
  assert.ok(list.at(-1).t - list[0].t > 10, "more than ten seconds");
});

test("the same packet on two links plays once, and our own announcements not at all", () => {
  const one = packets(recording);
  const twice = merge([one, one.map(p => ({ ...p, t: p.t + 0.002 }))]);
  assert.equal(twice.length, merge([one]).length, "the second link's copies dropped");
  const ours = Buffer.from(one.find(p => p.port === 50000).payload);
  ours.write("sequent\0", 12, "latin1");
  assert.ok(!merge([[{ t: 0, port: 50000, payload: ours }]]).length, "Sequent.app's own player left out");
  assert.throws(() => packets(Buffer.alloc(40)), /not a pcap/);
});
