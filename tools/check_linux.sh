#!/bin/sh
# Check the installed Linux helper as someone would run it: it decodes the
# CDJs as Sequent.app does, starts, listens on its Pro DJ Link ports, serves
# its WebSocket only to the right pages, and, with a display and a session
# bus, brings up its tray icon without an error. Run after installing the
# package; .github/workflows/linux.yml does, on clean Debian and Ubuntu.
set -eu
python3 tools/check_app.py /usr/bin/sequent

# Moved ports, so nothing on the network is touched, and announcing nothing.
export SEQUENT_PORT_OFFSET=1000 SEQUENT_WS_PORT=18795
handshake() {
  python3 - "$1" <<'PY'
import socket, sys
s = socket.create_connection(("127.0.0.1", 18795), timeout=3)
s.sendall(("GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
           "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
           f"Origin: {sys.argv[1]}\r\n\r\n").encode())
print(s.recv(4096).split(b"\r\n")[0].decode())
PY
}
check() {
  for _ in $(seq 20); do handshake https://turpin.studio >/dev/null 2>&1 && break; sleep 0.5; done
  ss -lun | grep -q ':51000 ' && ss -lun | grep -q ':51001 ' || { echo "no Pro DJ Link ports"; cat "$1"; exit 1; }
  handshake https://turpin.studio | grep -q ' 101 ' || { echo "the page was refused"; cat "$1"; exit 1; }
  handshake https://example.com | grep -q ' 403 ' || { echo "another site was let in"; cat "$1"; exit 1; }
  ! grep -q Traceback "$1" || { cat "$1"; exit 1; }
}

sequent --headless --listen-only > headless.log 2>&1 &
pid=$!
check headless.log
kill "$pid"; wait "$pid" 2>/dev/null || true
echo "headless: listens, serves the page and turns other sites away"

if command -v xvfb-run >/dev/null && command -v dbus-run-session >/dev/null; then
  xvfb-run -a dbus-run-session -- sequent --listen-only > tray.log 2>&1 &
  pid=$!
  check tray.log
  sleep 2
  ! grep -q "no tray icon" tray.log || { cat tray.log; exit 1; }
  ! grep -q Traceback tray.log || { cat tray.log; exit 1; }
  kill "$pid"; wait "$pid" 2>/dev/null || true
  echo "tray: starts with GTK and AppIndicator, no errors"
  cat tray.log
fi
