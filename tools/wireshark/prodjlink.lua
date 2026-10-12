-- Pro DJ Link for Wireshark: Pioneer and AlphaTheta players and mixers on
-- UDP 50000 to 50002, and a player's database server on TCP 12523.
--
-- Field names and layouts follow Deep Symmetry's DJ Link analysis,
-- https://djl-analysis.deepsymmetry.org/, which this rests on; each packet
-- type links to its page there. What we've seen ourselves on CDJ-3000Xs
-- (firmware 1.40) is marked "3000X". Written for Sequent
-- (https://turpin.studio), whose Sequent.app reads the same packets.
--
-- Install: copy into Wireshark's personal plugins folder (Help, About
-- Wireshark, Folders), or run tshark -X lua_script:prodjlink.lua.
-- Capture on the interfaces the decks are on (169.254.x.x). Players send
-- their status only to devices that have announced, so something must be
-- announcing (rekordbox, beat-link, Sequent.app) for status to appear.

local MAGIC = "Qspt1WmJOL"
local DOCS = "https://djl-analysis.deepsymmetry.org/djl-analysis/"

local p = Proto("prodjlink", "Pro DJ Link")

-- Packet types by port, with the Deep Symmetry page for each.
local TYPES = {
  [50000] = {
    [0x00] = { "Channel claim, stage 1", "startup.html" },
    [0x01] = { "Mixer assignment intention", "startup.html" },
    [0x02] = { "Channel claim, stage 2", "startup.html" },
    [0x03] = { "Mixer channel assignment", "startup.html" },
    [0x04] = { "Channel claim, final stage", "startup.html" },
    [0x05] = { "Mixer assignment finished", "startup.html" },
    [0x06] = { "Keep-alive", "startup.html" },
    [0x08] = { "Channel conflict", "startup.html" },
    [0x0a] = { "Initial announcement", "startup.html" },
  },
  [50001] = {
    [0x02] = { "Fader start", "mixer_integration.html" },
    [0x03] = { "Channels on air", "mixer_integration.html" },
    [0x0b] = { "Absolute position", "beats.html" },
    [0x26] = { "Master handoff request", "sync.html" },
    [0x27] = { "Master handoff response", "sync.html" },
    [0x28] = { "Beat", "beats.html" },
    [0x2a] = { "Sync control", "sync.html" },
  },
  [50002] = {
    [0x05] = { "Media query", "media.html" },
    [0x06] = { "Media response", "media.html" },
    [0x0a] = { "CDJ status", "vcdj.html" },
    [0x19] = { "Load track command", "loading_tracks.html" },
    [0x1a] = { "Load track acknowledgement", "loading_tracks.html" },
    [0x29] = { "Mixer status", "vcdj.html" },
    [0x34] = { "Load settings command", "loading_tracks.html" },
    -- Not in Deep Symmetry's list as of October 2026. Seen from CDJ-3000Xs,
    -- four times a second, sent only to the announcing device, whose player
    -- number is at 0x26.
    [0x80] = { "Unknown (3000X, to an announced device)", nil },
  },
}

local f = p.fields
f.magic = ProtoField.string("prodjlink.magic", "Magic")
f.kind = ProtoField.uint8("prodjlink.type", "Type", base.HEX)
f.name = ProtoField.string("prodjlink.name", "Device name")
f.device = ProtoField.uint8("prodjlink.device", "Device number")
f.lenr = ProtoField.uint16("prodjlink.lenr", "Bytes remaining")
f.docs = ProtoField.string("prodjlink.docs", "Documented at")

-- Keep-alive (0x06 on 50000).
f.ka_number = ProtoField.uint8("prodjlink.keepalive.number", "Player number")
f.ka_mac = ProtoField.ether("prodjlink.keepalive.mac", "MAC address")
f.ka_ip = ProtoField.ipv4("prodjlink.keepalive.ip", "IP address")

-- Beat (0x28 on 50001).
f.next_beat = ProtoField.uint32("prodjlink.beat.next_beat", "Next beat (ms)")
f.next_bar = ProtoField.uint32("prodjlink.beat.next_bar", "Next bar (ms)")
f.pitch = ProtoField.string("prodjlink.pitch", "Pitch")
f.bpm = ProtoField.string("prodjlink.bpm", "Track BPM")
f.beat_in_bar = ProtoField.uint8("prodjlink.beat.in_bar", "Beat in bar")

-- CDJ status (0x0a on 50002).
f.source = ProtoField.uint8("prodjlink.status.source", "Track source player")
f.slot = ProtoField.uint8("prodjlink.status.slot", "Track slot")
f.track_type = ProtoField.uint8("prodjlink.status.track_type", "Track type")
f.rekordbox_id = ProtoField.uint32("prodjlink.status.rekordbox_id", "rekordbox ID")
f.track_number = ProtoField.uint16("prodjlink.status.track_number", "Track number")
f.firmware = ProtoField.string("prodjlink.status.firmware", "Firmware")
f.flags = ProtoField.uint8("prodjlink.status.flags", "Flags", base.HEX)
f.playing = ProtoField.bool("prodjlink.status.playing", "Playing", 8, nil, 0x40)
f.master = ProtoField.bool("prodjlink.status.master", "Tempo master", 8, nil, 0x20)
f.sync = ProtoField.bool("prodjlink.status.sync", "Sync", 8, nil, 0x10)
f.on_air = ProtoField.bool("prodjlink.status.on_air", "On air", 8, nil, 0x08)
f.master_tempo = ProtoField.bool("prodjlink.status.master_tempo", "Master Tempo")
f.key = ProtoField.string("prodjlink.status.key", "Key")
f.key_shift = ProtoField.int64("prodjlink.status.key_shift", "Key Shift (cents)")
f.key_heard = ProtoField.string("prodjlink.status.key_heard", "Key heard (with Key Shift)")
f.candidate = ProtoField.uint32("prodjlink.status.x3000_candidate", "Changes with the track (3000X, meaning unknown)")

-- Type 0x80 on 50002.
f.x80_to = ProtoField.uint8("prodjlink.x80.to", "Addressed to player")

-- Database server (TCP).
local db = Proto("prodjlink_db", "Pro DJ Link database")
db.fields.kind = ProtoField.uint16("prodjlink_db.kind", "Message kind", base.HEX)
db.fields.tx = ProtoField.uint32("prodjlink_db.tx", "Transaction", base.HEX)
db.fields.args = ProtoField.uint8("prodjlink_db.args", "Arguments")
db.fields.num = ProtoField.uint32("prodjlink_db.number", "Number")
db.fields.str = ProtoField.string("prodjlink_db.string", "String")
db.fields.blob = ProtoField.bytes("prodjlink_db.blob", "Blob")

local NOTES = { "A", "B♭", "B", "C", "C♯", "D", "E♭", "E", "F", "F♯", "G", "A♭" }
local MAJOR = { "C", "D♭", "D", "E♭", "E", "F", "F♯", "G", "A♭", "A", "B♭", "B" }

-- A key from its note byte and major flag: minor keys count up from A and
-- major keys from C, so a key and its relative share a number.
local function key_name(note, major)
  if note > 11 then return nil end
  return major and MAJOR[note + 1] or NOTES[note + 1] .. "m"
end

local function pitch_text(raw)
  return string.format("%+.2f%%", (raw - 0x100000) / 0x100000 * 100)
end

local function bpm_text(raw)
  return raw == 0xffff and "none" or string.format("%.2f", raw / 100)
end

local function header(buf, tree, port)
  tree:add(f.magic, buf(0, 10))
  local kind = buf(0x0a, 1):uint()
  local known = (TYPES[port] or {})[kind]
  tree:add(f.kind, buf(0x0a, 1)):append_text(known and (" (" .. known[1] .. ")") or " (unknown)")
  if known and known[2] then tree:add(f.docs, DOCS .. known[2]) end
  return kind, known
end

local function keepalive(buf, tree)
  tree:add(f.name, buf(0x0c, 20))
  if buf:len() < 0x30 then return end
  tree:add(f.ka_number, buf(0x24, 1))
  tree:add(f.ka_mac, buf(0x26, 6))
  tree:add(f.ka_ip, buf(0x2c, 4))
end

local function named(buf, tree)
  tree:add(f.name, buf(0x0b, 20))
  if buf:len() < 0x24 then return end
  tree:add(f.device, buf(0x21, 1))
  tree:add(f.lenr, buf(0x22, 2))
end

local function beat(buf, tree)
  if buf:len() < 0x60 then return end
  tree:add(f.next_beat, buf(0x24, 4))
  tree:add(f.next_bar, buf(0x2c, 4))
  tree:add(f.pitch, buf(0x54, 4), pitch_text(buf(0x54, 4):uint()))
  tree:add(f.bpm, buf(0x5a, 2), bpm_text(buf(0x5a, 2):uint()))
  tree:add(f.beat_in_bar, buf(0x5c, 1))
end

local function status(buf, tree, pinfo)
  if buf:len() < 0x94 then return end
  tree:add(f.source, buf(0x28, 1))
  tree:add(f.slot, buf(0x29, 1))
  tree:add(f.track_type, buf(0x2a, 1))
  tree:add(f.rekordbox_id, buf(0x2c, 4))
  tree:add(f.track_number, buf(0x32, 2))
  tree:add(f.firmware, buf(0x7c, 4))
  local flags = tree:add(f.flags, buf(0x89, 1))
  flags:add(f.playing, buf(0x89, 1))
  flags:add(f.master, buf(0x89, 1))
  flags:add(f.sync, buf(0x89, 1))
  flags:add(f.on_air, buf(0x89, 1))
  tree:add(f.pitch, buf(0x8c, 4), pitch_text(buf(0x8c, 4):uint()))
  local bpm = buf(0x92, 2):uint()
  tree:add(f.bpm, buf(0x92, 2), bpm_text(bpm))
  local info = string.format("player %d, %s BPM", buf(0x21, 1):uint(), bpm_text(bpm))
  if buf:len() >= 0x16c then
    tree:add(f.master_tempo, buf(0x158, 1))
    local note, major = buf(0x15c, 1):uint(), buf(0x15d, 1):uint() == 1
    local name = key_name(note, major)
    tree:add(f.key, buf(0x15c, 3), name or "none")
    local shift = buf(0x164, 8):int64()
    tree:add(f.key_shift, buf(0x164, 8))
    if name and bpm ~= 0xffff then
      local steps = math.floor(shift:tonumber() / 100 + 0.5)
      local heard = major and MAJOR[(note + steps) % 12 + 1] or NOTES[(note + steps) % 12 + 1] .. "m"
      tree:add(f.key_heard, buf(0x164, 8), heard)
      info = info .. ", " .. heard
    end
  end
  -- The 3000X's 1152-byte status leaves the documented track identity
  -- zero; these change with the track instead, and repeat from 0x18c.
  if buf:len() == 0x480 then
    local x = tree:add(p, buf(0x34, 0x14), "3000X: values that change with the track")
    for _, at in ipairs({ 0x34, 0x38, 0x3c, 0x40, 0x44 }) do
      x:add(f.candidate, buf(at, 4)):prepend_text(string.format("0x%02x: ", at))
    end
    x:add(f.candidate, buf(0x194, 4)):prepend_text("0x194: ")
  end
  pinfo.cols.info:append(" " .. info)
end

function p.dissector(buf, pinfo, tree)
  if buf:len() < 0x0b or buf(0, 10):string() ~= MAGIC then return 0 end
  pinfo.cols.protocol = "ProDJLink"
  local port = pinfo.dst_port
  if not TYPES[port] then port = pinfo.src_port end
  local t = tree:add(p, buf(), "Pro DJ Link")
  local kind, known = header(buf, t, port)
  pinfo.cols.info = known and known[1] or string.format("Type 0x%02x on %d", kind, port)
  if port == 50000 then
    if kind == 0x06 then keepalive(buf, t) end
    return buf:len()
  end
  named(buf, t)
  if port == 50001 and kind == 0x28 then beat(buf, t)
  elseif port == 50002 and kind == 0x0a then status(buf, t, pinfo)
  elseif port == 50002 and kind == 0x80 and buf:len() >= 0x27 then
    t:add(f.x80_to, buf(0x26, 1))
  end
  return buf:len()
end

-- The database server's messages are typed fields: 0x0f, 0x10 and 0x11
-- numbers of 1, 2 and 4 bytes, 0x14 a blob and 0x26 a UTF-16 string, each
-- with a 4-byte length. Every message starts with the number 0x872349ae.
local DB_KINDS = {
  [0x0000] = "Setup", [0x0100] = "Teardown", [0x2002] = "Metadata request",
  [0x3000] = "Render menu", [0x4000] = "Success", [0x4001] = "Menu header",
  [0x4101] = "Menu item", [0x4201] = "Menu footer",
}

local function field_at(buf, at)
  if at >= buf:len() then return nil end
  local tag = buf(at, 1):uint()
  local size = ({ [0x0f] = 1, [0x10] = 2, [0x11] = 4 })[tag]
  if size then
    if at + 1 + size > buf:len() then return nil end
    return at + 1 + size, "number", buf(at + 1, size)
  end
  if tag == 0x14 or tag == 0x26 then
    if at + 5 > buf:len() then return nil end
    local n = buf(at + 1, 4):uint() * (tag == 0x26 and 2 or 1)
    if at + 5 + n > buf:len() then return nil end
    return at + 5 + n, tag == 0x26 and "string" or "blob", n > 0 and buf(at + 5, n) or nil
  end
  return nil
end

function db.dissector(buf, pinfo, tree)
  local at = 0
  while at + 5 <= buf:len() and buf(at, 5):uint64():tonumber() == 0x11872349ae do
    local start = at
    local m = tree:add(db, buf(at), "Database message")
    local nxt, _, v = field_at(buf, at + 5)
    if not nxt then pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT; pinfo.desegment_offset = start; return end
    m:add(db.fields.tx, v)
    local kind
    nxt, _, v = field_at(buf, nxt); if not nxt then return end
    kind = v:uint(); m:add(db.fields.kind, v):append_text(" (" .. (DB_KINDS[kind] or "?") .. ")")
    local count
    nxt, _, v = field_at(buf, nxt); if not nxt then return end
    count = v:uint(); m:add(db.fields.args, v)
    nxt = field_at(buf, nxt); if not nxt then return end
    for _ = 1, count do
      local after, what, val = field_at(buf, nxt)
      if not after then pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT; pinfo.desegment_offset = start; return end
      if what == "number" then m:add(db.fields.num, val)
      elseif what == "string" and val then m:add(db.fields.str, val, val:ustring())
      elseif val then m:add(db.fields.blob, val) end
      nxt = after
    end
    m:set_len(nxt - start)
    pinfo.cols.protocol = "ProDJLink DB"
    pinfo.cols.info = DB_KINDS[kind] or string.format("Database kind 0x%04x", kind)
    at = nxt
  end
end

local udp = DissectorTable.get("udp.port")
for port = 50000, 50002 do udp:add(port, p) end
DissectorTable.get("tcp.port"):add(12523, db)
-- The database server hands out a second port to talk on, so its messages
-- are also recognised by their opening number wherever they turn up.
db:register_heuristic("tcp", function(buf, pinfo, tree)
  if buf:len() < 5 or buf(0, 5):uint64():tonumber() ~= 0x11872349ae then return false end
  db.dissector(buf, pinfo, tree)
  return true
end)
