// Play recorded Pro DJ Link traffic back into Sequent.app, at the timing it
// was recorded with, so the page follows decks that aren't there (make
// replay). The recording is the files tools/djlink-record.sh wrote, one per
// interface, merged in time order with the copies dropped (each packet
// arrives once per USB link), and Sequent.app's own announcements left out.
//
//   node tools/djlink-replay.mjs NAME [--loop] [--speed 2]
//
// The packets go to this Mac, 127.0.0.1, on the Pro DJ Link ports, where the
// running Sequent.app reads them as it reads the decks; SEQUENT_PORT_OFFSET
// moves them as it moves the app's. Quit rekordbox first, as for real decks.
// Track titles won't appear: the app looks those up on the decks
// themselves, which aren't there.
import { readFileSync, readdirSync } from "node:fs";
import { createSocket } from "node:dgram";

const MAGIC = Buffer.from("Qspt1WmJOL");
const DIR = new URL("recordings/", import.meta.url);

// The UDP payloads in a classic pcap file, with their times in seconds.
export function packets(data) {
  const magic = data.readUInt32LE(0);
  const nano = magic === 0xa1b23c4d;
  if (magic !== 0xa1b2c3d4 && !nano) throw new Error("not a pcap file (tcpdump -w writes one)");
  const link = data.readUInt32LE(20);
  const out = [];
  for (let i = 24; i + 16 <= data.length;) {
    const t = data.readUInt32LE(i) + data.readUInt32LE(i + 4) / (nano ? 1e9 : 1e6);
    const len = data.readUInt32LE(i + 8);
    const frame = data.subarray(i + 16, i + 16 + len);
    i += 16 + len;
    // Ethernet, or the BSD loopback header, then IPv4 and UDP.
    const ip = link === 1 ? 14 : link === 0 || link === 108 ? 4 : -1;
    if (ip < 0 || frame.length < ip + 28 || frame[ip] >> 4 !== 4 || frame[ip + 9] !== 17) continue;
    const udp = ip + (frame[ip] & 15) * 4;
    const port = frame.readUInt16BE(udp + 2), payload = frame.subarray(udp + 8);
    if (payload.subarray(0, 10).equals(MAGIC)) out.push({ t, port, payload });
  }
  return out;
}

// Every interface's file for a recording, merged: in time order, a payload
// seen again within 50 ms dropped, as the app drops it, and our own player's
// announcements ("sequent", player 7) left out.
export function merge(lists) {
  const all = lists.flat().sort((a, b) => a.t - b.t);
  const seen = new Map(), out = [];
  for (const p of all) {
    const key = p.payload.toString("hex");
    if (seen.has(key) && p.t - seen.get(key) < 0.05) continue;
    seen.set(key, p.t);
    if (p.port === 50000 && p.payload.subarray(12, 19).toString() === "sequent") continue;
    out.push(p);
  }
  return out;
}

function load(name) {
  const files = readdirSync(DIR).filter(f => f.startsWith(`${name}-`) && f.endsWith(".pcap"));
  if (!files.length) throw new Error(`no recording ${name} in tools/recordings`);
  return merge(files.map(f => packets(readFileSync(new URL(f, DIR)))));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2);
  const name = args.find(a => !a.startsWith("--") && !/^[\d.]+$/.test(a));
  if (!name) { console.log("usage: node tools/djlink-replay.mjs NAME [--loop] [--speed 2]"); process.exit(1); }
  const loop = args.includes("--loop");
  const speed = Number(args[args.indexOf("--speed") + 1]) || 1;
  const offset = Number(process.env.SEQUENT_PORT_OFFSET) || 0;
  const list = load(name);
  const length = list.at(-1).t - list[0].t;
  const kinds = list.reduce((m, p) => ({ ...m, [p.port]: (m[p.port] ?? 0) + 1 }), {});
  console.log(`${name}: ${list.length} packets over ${length.toFixed(1)} s (announcements ${kinds[50000] ?? 0}, beats ${kinds[50001] ?? 0}, status ${kinds[50002] ?? 0})${loop ? ", looping" : ""}`);
  const socket = createSocket("udp4");
  let round = 0;
  const play = () => {
    const start = performance.now() / 1000;
    let i = 0;
    const next = () => {
      while (i < list.length && (list[i].t - list[0].t) / speed <= performance.now() / 1000 - start) {
        const p = list[i++];
        socket.send(p.payload, p.port + offset, "127.0.0.1");
      }
      if (i < list.length) return setTimeout(next, Math.max(0, ((list[i].t - list[0].t) / speed - (performance.now() / 1000 - start)) * 1000));
      round++;
      if (loop) { console.log(`round ${round} done, again`); return play(); }
      socket.close();
      console.log("done");
    };
    next();
  };
  play();
}
