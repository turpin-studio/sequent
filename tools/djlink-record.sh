#!/bin/sh
# Record the CDJs' Pro DJ Link traffic, to play back later with
# tools/djlink_replay.py and test the page with no decks (make record).
#
#   tools/djlink-record.sh NAME [SECONDS]
#
# Sequent.app must be running, or the players send no status: they send it
# only to devices that have announced, and the app announces as player 7.
# Every link-local interface (a USB cable to a CDJ, or an Ethernet link) is
# captured to its own file, NAME-<interface>.pcap in tools/recordings, since
# macOS's tcpdump captures one interface at a time; the replayer merges them
# and drops the copies, as the app does. Needs packet capture rights, which
# Wireshark's ChmodBPF gives without sudo.
set -eu
name=${1:?usage: djlink-record.sh NAME [SECONDS]}
seconds=${2:-120}
dir=$(cd "$(dirname "$0")" && pwd)/recordings
mkdir -p "$dir"

links=$(ifconfig | awk '/^[a-z]/ { i = $1; sub(":", "", i) } /inet 169\.254\./ { print i }')
[ -n "$links" ] || { echo "No link-local interface: connect a CDJ by USB or Ethernet first."; exit 1; }
pgrep -f 'Sequent.app/Contents/MacOS/Sequent' >/dev/null || echo "Sequent.app isn't running: the decks will send beats but no status."

pids=""
for i in $links; do
  tcpdump -i "$i" -n -q -w "$dir/$name-$i.pcap" 'udp and portrange 50000-50002' 2>/dev/null &
  pids="$pids $!"
  echo "Recording $i to tools/recordings/$name-$i.pcap"
done
trap 'kill $pids 2>/dev/null' INT TERM
echo "For $seconds seconds: play, change tracks, stop and start, move the tempo."
sleep "$seconds"
kill $pids 2>/dev/null
wait 2>/dev/null || true
for i in $links; do
  echo "$(tcpdump -r "$dir/$name-$i.pcap" 2>/dev/null | wc -l | tr -d ' ') packets on $i"
done
echo "Play it back with: make replay FILE=$name"
