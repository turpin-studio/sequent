"""Play recorded Pro DJ Link traffic back into a running bridge, at the timing
it was recorded with, so it and the page follow decks that aren't there
(make replay).

    python3 tools/djlink_replay.py NAME [--loop] [--speed 2]

The recording is the files tools/djlink-record.sh wrote, one per interface,
merged in time order with the copies dropped (each packet arrives once per
USB link), and the bridge's own announcements left out. The packets go to
this computer, 127.0.0.1, on the Pro DJ Link ports, where the running
Sequent.app or Sequent for Linux reads them as it reads the decks;
SEQUENT_PORT_OFFSET moves them as it moves the bridge's. Quit rekordbox
first, as for real decks. Track titles won't appear: the bridge looks those
up on the decks themselves, which aren't there.

Standard library only.
"""
import os
import pathlib
import socket
import struct
import sys
import time

MAGIC = b"Qspt1WmJOL"
RECORDINGS = pathlib.Path(__file__).resolve().parent / "recordings"
ANNOUNCE_PORT = 50000
DUPLICATE_WINDOW_S = 0.05


def packets(data):
    """The Pro DJ Link UDP payloads in a classic pcap file, as
    [(seconds, port, payload)]."""
    if len(data) < 24:
        raise ValueError("not a pcap file (tcpdump -w writes one)")
    magic = struct.unpack_from("<I", data, 0)[0]
    nano = magic == 0xa1b23c4d
    if magic != 0xa1b2c3d4 and not nano:
        raise ValueError("not a pcap file (tcpdump -w writes one)")
    link = struct.unpack_from("<I", data, 20)[0]
    # Ethernet, or the BSD loopback header, then IPv4 and UDP.
    ip = 14 if link == 1 else 4 if link in (0, 108) else -1
    out, i = [], 24
    while i + 16 <= len(data):
        seconds, fraction, length = struct.unpack_from("<III", data, i)
        frame = data[i + 16:i + 16 + length]
        i += 16 + length
        if ip < 0 or len(frame) < ip + 28 or frame[ip] >> 4 != 4 or frame[ip + 9] != 17:
            continue
        udp = ip + (frame[ip] & 15) * 4
        port = struct.unpack_from(">H", frame, udp + 2)[0]
        payload = frame[udp + 8:]
        if payload.startswith(MAGIC):
            out.append((seconds + fraction / (1e9 if nano else 1e6), port, payload))
    return out


def merge(lists):
    """Every interface's packets for a recording, merged: in time order, a
    payload seen again within 50 ms dropped, as the bridge drops it, and our
    own player's announcements ("sequent", player 7) left out."""
    seen, out = {}, []
    for t, port, payload in sorted((p for ps in lists for p in ps), key=lambda p: p[0]):
        if payload in seen and t - seen[payload] < DUPLICATE_WINDOW_S:
            continue
        seen[payload] = t
        if port == ANNOUNCE_PORT and payload[12:19] == b"sequent":
            continue
        out.append((t, port, payload))
    return out


def load(name, directory=RECORDINGS):
    files = sorted(directory.glob(f"{name}-*.pcap"))
    if not files:
        raise SystemExit(f"no recording {name} in {directory}")
    return merge([packets(f.read_bytes()) for f in files])


def play(packets_, speed=1.0, offset=0, send=None, clock=time.monotonic, sleep=time.sleep):
    """Send each packet when its moment comes, relative to the first."""
    if send is None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        send = lambda port, payload: sock.sendto(payload, ("127.0.0.1", port))
    # Sleep until a few milliseconds short, then wait out the rest, since a
    # sleep can overrun by several milliseconds on macOS and the page
    # measures beat jitter. It costs some CPU, which a test tool can spare.
    first, start = packets_[0][0], clock()
    for t, port, payload in packets_:
        due = start + (t - first) / speed
        if due - clock() > 0.005:
            sleep(due - clock() - 0.004)
        while clock() < due:
            pass
        send(port + offset, payload)


def main(argv):
    names = [a for i, a in enumerate(argv) if not a.startswith("--") and (i == 0 or argv[i - 1] != "--speed")]
    if not names:
        raise SystemExit("usage: python3 tools/djlink_replay.py NAME [--loop] [--speed 2]")
    loop = "--loop" in argv
    speed = float(argv[argv.index("--speed") + 1]) if "--speed" in argv else 1.0
    offset = int(os.environ.get("SEQUENT_PORT_OFFSET") or 0)
    list_ = load(names[0])
    count = lambda port: sum(1 for _, p, _ in list_ if p == port)
    print(f"{names[0]}: {len(list_)} packets over {list_[-1][0] - list_[0][0]:.1f} s "
          f"(announcements {count(50000)}, beats {count(50001)}, status {count(50002)})"
          f"{', looping' if loop else ''}", flush=True)
    round_ = 0
    while True:
        play(list_, speed, offset)
        round_ += 1
        if not loop:
            break
        print(f"round {round_} done, again", flush=True)
    print("done")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except KeyboardInterrupt:
        pass
