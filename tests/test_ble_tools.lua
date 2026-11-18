-- test_ble_tools.lua
--
-- Pure Lua unit test of BLE_Tools.lua (no Wireshark needed). The Wireshark API pieces used by
-- the module (Field.new, FieldInfo.range:tvb(), Tvb range access) are replaced by small stubs.
--
-- Run from the repository root:  lua5.4 tests/test_ble_tools.lua
-- Exit code 0 = all tests passed.

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
Field = { new = function(name)
    assert(name == "btle", "BLE_Tools must only create the btle field")
    return function() return currentField end
end }

local BleTools = require("BLE_Tools")

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

check("ADV_DATA_OFFSET is 12", BleTools.ADV_DATA_OFFSET == 12)

if failures > 0 then
    print(failures .. " test(s) failed")
    os.exit(1)
end
print("all tests passed")
