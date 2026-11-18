-- test_ble_tools.lua
--
-- Pure Lua unit test of BLE_Tools.lua (no Wireshark needed). The Wireshark API pieces used by
-- the module (Field.new, FieldInfo.range:tvb(), Tvb range access) are replaced by small stubs.
--
-- Run from the repository root:  lua5.4 tests/test_ble_tools.lua
-- Exit code 0 = all tests passed.

-- Wireshark loads every .lua file below its plugin directory, also this one when the repository
-- is cloned into the personal plugins folder. Inside Wireshark the global Proto exists: do
-- nothing then, so the stubs below can never replace the real Field API.
if Proto ~= nil then
    return
end

-- Locate the repository root from this script's path and extend package.path.
local script = debug.getinfo(1, "S").source:sub(2)
local root = (script:match("(.+)[/\\]tests[/\\]") or ".")
package.path = package.path .. ";" .. root .. "/?.lua"

-- ---------------------------------------------------------------------------
-- Stubs
-- ---------------------------------------------------------------------------

--- Build a fake Tvb from a byte string. tvb(off, len) returns a range with :uint()/:le_uint().
-- Like the real API, out-of-range access raises an error.
local function makeTvb(bytes)
    local tvb = { len = function() return #bytes end }
    return setmetatable(tvb, { __call = function(_, off, len)
        if off < 0 or len < 1 or off + len > #bytes then
            error("Range is out of bounds")
        end
        local value, le_value = 0, 0
        for i = 0, len - 1 do
            value = value * 256 + bytes:byte(off + 1 + i)             -- big endian
            le_value = le_value + bytes:byte(off + 1 + i) * 256 ^ i   -- little endian
        end
        return { uint = function() return value end,
                 le_uint = function() return math.tointeger(le_value) or le_value end }
    end })
end

-- The frame the stub Field returns: nil (no btle field), or a FieldInfo whose range:tvb()
-- yields the LL packet re-based at offset 0 - regardless of junk bytes before it in the frame.
local currentField
local originalField = Field          -- restored after loading the module: no global leaks
Field = { new = function(name)
    assert(name == "btle", "BLE_Tools must only create the btle field")
    return function() return currentField end
end }

local BleTools = require("BLE_Tools")
Field = originalField               -- the module keeps its own reference to the stub extractor

--- Little endian access address as a byte string.
local function aaBytes(aa)
    return string.char(aa & 0xFF, (aa >> 8) & 0xFF, (aa >> 16) & 0xFF, (aa >> 24) & 0xFF)
end

--- Build an LL advertising packet: AA + header + AdvA + advLen bytes + 3 byte CRC.
local function llPacket(advLen, aa, pduLenOverride)
    local pduLen = pduLenOverride or (6 + advLen)
    return aaBytes(aa or BleTools.ADV_ACCESS_ADDRESS) .. string.char(0x42, pduLen)
        .. string.rep("\x11", 6) .. string.rep("\xAA", advLen) .. "\x01\x02\x03"
end

--- Install a btle field whose range holds the given LL packet (junk bytes precede it in the frame).
local function setFrame(ll, junkBefore)
    -- the junk is only part of the (unused) frame; range:tvb() re-bases to the LL packet
    local junk = string.rep("\xEE", junkBefore or 0)
    currentField = { range = { tvb = function() return makeTvb(ll) end }, frame = junk .. ll }
end

-- ---------------------------------------------------------------------------
-- Tests
-- ---------------------------------------------------------------------------
local failures = 0
local function check(name, ok)
    print((ok and "ok   " or "FAIL ") .. name)
    if not ok then failures = failures + 1 end
end

-- valid packet, independent of the amount of bytes in front of it (DLT 251 / 256 / 272)
for _, junk in ipairs({ 0, 10, 17 }) do
    setFrame(llPacket(31), junk)
    local ll, advLen = BleTools.getLinkLayer()
    check("valid packet, " .. junk .. " junk bytes: advLen 31", ll ~= nil and advLen == 31)
    check("valid packet, " .. junk .. " junk bytes: starts at access address",
          ll ~= nil and ll(0, 4):le_uint() == 0x8E89BED6)
    check("valid packet, " .. junk .. " junk bytes: adv data at ADV_DATA_OFFSET",
          ll ~= nil and ll(BleTools.ADV_DATA_OFFSET, 1):uint() == 0xAA)
end

-- other adv data lengths used by the dissectors
for _, n in ipairs({ 23, 25, 26, 30 }) do
    setFrame(llPacket(n))
    local _, advLen = BleTools.getLinkLayer()
    check("advLen " .. n, advLen == n)
end

currentField = nil
check("no btle field -> nil", BleTools.getLinkLayer() == nil)

setFrame(llPacket(31, 0x12345678))
check("data channel access address -> nil", BleTools.getLinkLayer() == nil)

setFrame(llPacket(31):sub(1, 30))
check("truncated packet -> nil", BleTools.getLinkLayer() == nil)

setFrame(llPacket(31):sub(1, 8))
check("shorter than AA+header+AdvA -> nil", BleTools.getLinkLayer() == nil)

setFrame(llPacket(0, nil, 5))
check("PDU length < 6 -> nil", BleTools.getLinkLayer() == nil)

currentField = { range = { tvb = function() error("boom") end } }
check("range:tvb() error -> nil (no exception)", BleTools.getLinkLayer() == nil)

-- ---------------------------------------------------------------------------
-- matches()
-- ---------------------------------------------------------------------------
local ll12 = makeTvb(string.char(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15))
check("matches: all bytes equal", BleTools.matches(ll12, 0, { { 1, 1 }, { 3, 3 }, { 15, 15 } }))
check("matches: with base offset", BleTools.matches(ll12, 10, { { 0, 10 }, { 5, 15 } }))
check("matches: virtual base before the data", BleTools.matches(ll12, 12 - 3, { { 3, 12 }, { 4, 13 } }))
check("matches: mismatch -> false", not BleTools.matches(ll12, 0, { { 1, 1 }, { 2, 99 } }))
check("matches: first mismatch stops (later out-of-range offset is not read)",
      not BleTools.matches(ll12, 0, { { 1, 99 }, { 500, 0 } }))
check("matches: offset behind the packet -> false, no error", not BleTools.matches(ll12, 0, { { 16, 0 } }))
check("matches: offset before the packet -> false, no error", not BleTools.matches(ll12, 0, { { -1, 0 } }))
check("matches: empty pattern matches", BleTools.matches(ll12, 0, {}))

-- ---------------------------------------------------------------------------
-- hex() / describe(): a ByteArray stub with 0 based get_index
-- ---------------------------------------------------------------------------
local function makeBytes(...)
    local list = { ... }
    return { get_index = function(_, i) return list[i + 1] end, len = function() return #list end }
end
local datagram = makeBytes(0x66, 0x7b, 0xa7, 0x80, 0x80, 0x80, 0x4f, 0x99)
check("hex: range", BleTools.hex(datagram, 3, 5) == " 80 80 80")
check("hex: single byte", BleTools.hex(datagram, 2, 2) == " a7")
check("hex: empty range", BleTools.hex(datagram, 4, 3) == "")
check("hex: lower case, zero padded", BleTools.hex(makeBytes(0x0a, 0xFF), 0, 1) == " 0a ff")
check("describe: id only", BleTools.describe(datagram, 0) == "Cmd[66] ID[7b a7]")
check("describe: 4 data bytes", BleTools.describe(datagram, 4) == "Cmd[66] ID[7b a7] 80 80 80 4f")
check("describe: 6 data bytes", BleTools.describe(makeBytes(0x7d, 0x7b, 0xa7, 1, 2, 3, 4, 5, 6, 0x82), 6)
      == "Cmd[7d] ID[7b a7] 01 02 03 04 05 06")

-- ---------------------------------------------------------------------------
-- addPayloadTrees(): record what is added to a fake tree
-- ---------------------------------------------------------------------------
local added = {}
local function fakeSubtree(label)
    return { add = function(_, _, text) added[#added + 1] = (text or "") end,
             label = label }
end
local fakeTree = { add = function(_, _, _, label)
    added[#added + 1] = label
    return fakeSubtree(label)
end }
local originalByteArray = ByteArray
-- ByteArray.tvb(bytes, name) returns a function that yields a range with :len()
ByteArray = { tvb = function(bytes) return function() return { len = function() return bytes:len() end } end end }
local function treeLines(tree, decrypted)
    added = {}
    BleTools.addPayloadTrees(tree, {}, "info", "Android", "MouldKing", makeBytes(1, 2, 3), decrypted, "X Connect")
    return table.concat(added, "|")
end
check("addPayloadTrees: builds both subtrees",
      treeLines(fakeTree, datagram) ==
      "Android - MouldKing - Payload|Len: 3|Android - MouldKing - decrypted|X Connect-Datagram - Len: 8")
check("addPayloadTrees: no tree -> nothing", treeLines(nil, datagram) == "")
check("addPayloadTrees: no decrypted data -> nothing", treeLines(fakeTree, nil) == "")

-- With ProtoFields: the datagram line keeps its text, everything else is hidden.
local items = {}
local function recordingSubtree()
    return { add = function(self, field, _, value, label)
        local item = { field = type(field) == "table" and field.name or nil, value = value, label = label,
                       set_hidden = function(this) this.hidden = true end }
        items[#items + 1] = item
        return item.field and item or recordingSubtree()
    end }
end
local fieldTree = { add = function(_, _, _, label) items[#items + 1] = { label = label }; return recordingSubtree() end }
-- ProtoField stub: a table with a name; base.HEX only has to exist
local originalProtoField, originalBase = ProtoField, base
base = { HEX = 1 }
local function stubField(abbrev) return { name = abbrev } end
ProtoField = { string = stubField, bytes = stubField, uint8 = stubField, uint16 = stubField }
local fields, fieldList = BleTools.newDatagramFields("mk")
check("newDatagramFields: abbreviations carry the prefix", fields.cmd.name == "mk.cmd" and fields.id.name == "mk.id")
check("newDatagramFields: list holds all 7 fields", #fieldList == 7)
items = {}
BleTools.addPayloadTrees(fieldTree, {}, "info", "Android", "MouldKing", makeBytes(1, 2, 3), datagram, "X Connect", fields)
local seen = {}
for _, item in ipairs(items) do
    if item.field then seen[item.field] = item end
end
check("addPayloadTrees+fields: datagram line keeps its text",
      seen["mk.datagram"] and seen["mk.datagram"].label == "X Connect-Datagram - Len: 8"
      and seen["mk.datagram"].value == "X Connect" and not seen["mk.datagram"].hidden)
check("addPayloadTrees+fields: cmd/id/data/platform/manufacturer/payload are hidden",
      seen["mk.cmd"] and seen["mk.cmd"].hidden and seen["mk.id"].hidden and seen["mk.data"].hidden
      and seen["mk.platform"].hidden and seen["mk.manufacturer"].hidden and seen["mk.payload"].hidden)
check("addPayloadTrees+fields: string fields carry their value",
      seen["mk.platform"].value == "Android" and seen["mk.manufacturer"].value == "MouldKing")
ProtoField, base = originalProtoField, originalBase
ByteArray = originalByteArray

check("ADV_DATA_OFFSET is 12", BleTools.ADV_DATA_OFFSET == 12)

if failures > 0 then
    print(failures .. " test(s) failed")
    os.exit(1)
end
print("all tests passed")
