-- PowerBox.lua
--
-- Wireshark post-dissector for the Bluetooth LE advertising datagrams of the MouldKing
-- "PowerBox" (Android, Windows and iOS app). The advertising payload is decrypted with
-- Crypt_Tools and shown in the Info column and in the packet tree.
--
-- Structure of this file: preamble -> constants/tables -> helpers -> dissector -> registration.
-- A new platform variant is added as one more row of VARIANTS.

-- Preamble: make the helper modules next to this script loadable with require(). Wireshark
-- only loads the scripts, it does not add their folder to package.path.
local script = debug.getinfo(1, "S").source:sub(2)
local bindir = script:match("(.+)[/\\]") or "."          -- folder of this script
local searchPath = ";" .. bindir .. "/?.lua"
if not package.path:find(searchPath, 1, true) then      -- do not append the same path twice
    package.path = package.path .. searchPath
end

local BleTools = require("BLE_Tools")
local CryptTools = require("Crypt_Tools")

-- Protocol object of this post-dissector (used as the owner of the tree items).
local PowerBoxDissector = Proto("PowerBox", "Global Frame Analyzer for Bluetooth LE from PowerBox")

-- Decryption parameters (identical for all platforms).
local SEED = { 0xC1, 0xC2, 0xC3, 0xC4, 0xC5 }
local CTX_VALUE_1 = 0x3f
local CTX_VALUE_2 = 0x25
local HEADER_LENGTH = 3     -- bytes of the decrypted header (command + 2 byte device id)
local DATA_LENGTH = 8       -- bytes of the decrypted datagram (command, id, 4 data bytes, checksum)

-- Offset base of the variant rows. All "offset" values below are relative to the base.
local ADV_DATA = BleTools.ADV_DATA_OFFSET

-- Variant table, one row per platform, tried in this order.
--   platform     shown in the Info column
--   advLen       exact length of the advertising data
--   base         offset the pattern and rawOffset are relative to
--   pattern      identifying bytes as {offset, value} pairs (everything else is "don't care")
--   rawOffset    where the encrypted payload starts (relative to base)
--   rawLength    length of the encrypted payload
--   headerOffset position of the header in the whitening sequence (see Crypt_Tools)
local VARIANTS = {
    {
        platform = "Android",
        advLen = 25,
        base = ADV_DATA,
        pattern = {
            { 3, 0x15 },    -- AD length: 21
            { 4, 0xff },    -- AD type: Manufacturer Specific (0xff)
            { 5, 0x00 },    -- company id 0xff00 ...
            { 6, 0xff },
            { 7, 0x6d },    -- identifier (first bytes of the encrypted payload)
            { 8, 0xb6 },
            { 9, 0x43 },
            { 10, 0xcf },
            { 11, 0x7e },
            { 12, 0x8f },
            { 13, 0x47 },
        },
        rawOffset = 7,
        rawLength = 19,
        headerOffset = 15,
    },
    {
        -- This packet has no Flags AD, the manufacturer AD starts directly at the advertising
        -- data start. The pattern is written with a "+ 3" shift like the other variants, so
        -- the base is a virtual one: 3 bytes BEFORE the real data start.
        platform = "Windows",
        advLen = 30,
        base = ADV_DATA - 3,
        pattern = {
            { 3, 0x1d },    -- AD length: 29
            { 4, 0xff },    -- AD type: Manufacturer Specific (0xff)
            { 5, 0x00 },    -- company id 0xff00 ...
            { 6, 0xff },
            { 7, 0x00 },
            { 8, 0x00 },
            { 9, 0x00 },
            { 10, 0x6d },   -- identifier (first bytes of the encrypted payload)
            { 11, 0xb6 },
            { 12, 0x43 },
            { 13, 0xcf },
            -- offset 14..15 (0x7e 0x8f): rest of the identifier, not checked
        },
        rawOffset = 10,
        rawLength = 18,
        headerOffset = 15,
    },
    {
        platform = "iOS",
        advLen = 26,
        base = ADV_DATA,
        pattern = {
            { 6, 0x13 },    -- AD length: 19
            { 7, 0x03 },    -- AD type: 16-bit Service Class UUIDs (0x03)
            { 8, 0xc8 },    -- first byte of the encrypted payload (identifier)
            -- offset 9..15: rest of the identifier (0x19 0x00 0x00 0x00 0x6d 0xb6 ...), not checked
        },
        rawOffset = 8,
        rawLength = 18,
        headerOffset = 16,
    },
}

--- Find the variant row whose identifier matches the advertising data.
-- @param ll     Tvb of the LL packet
-- @param advLen length of the advertising data
-- @return the matching row of VARIANTS or nil
local function findVariant(ll, advLen)
    for _, variant in ipairs(VARIANTS) do
        if advLen == variant.advLen and BleTools.matches(ll, variant.base, variant.pattern) then
            return variant
        end
    end
    return nil
end

--- Build manufacturer and datagram name for a decrypted datagram.
-- @param datagram decrypted datagram (ByteArray)
-- @return manufacturer, datagramname
local function describeDatagram(datagram)
    local command = datagram:get_index(0)
    if command == 0xa4 then
        -- Connect: only the device id is of interest.
        return "PowerBox", "Connect " .. BleTools.describe(datagram, 0)
    elseif command == 0x40 then
        -- Command: device id followed by 4 data bytes.
        return "PowerBox", "Command " .. BleTools.describe(datagram, 4)
    end
    return "Unknown", string.format("unknown - 0x%02x", command)
end

--- Post-dissector function, called by Wireshark for every frame.
-- Leaves frames alone that are not PowerBox advertising packets (returns 0).
function PowerBoxDissector.dissector(buffer, pinfo, tree)
    -- Locate the BLE link layer packet (independent of the capture link type);
    -- ll starts at the access address, advLen is the length of the advertising data.
    local ll, advLen = BleTools.getLinkLayer()
    if not ll then
        return 0
    end

    local variant = findVariant(ll, advLen)
    if not variant then
        return 0
    end

    -- Decrypt the payload.
    local encrypted = ll(variant.base + variant.rawOffset, variant.rawLength):bytes()
    local decrypted = CryptTools.DecryptRfPayload(SEED, HEADER_LENGTH, DATA_LENGTH,
        variant.headerOffset, CTX_VALUE_1, CTX_VALUE_2, encrypted)

    local manufacturer = "PowerBox"
    local datagramname
    if decrypted then
        manufacturer, datagramname = describeDatagram(decrypted)
    else
        datagramname = "Decryption failed"
    end

    local frameinfo = variant.platform .. " - " .. manufacturer .. " - " .. datagramname
    BleTools.addPayloadTrees(tree, PowerBoxDissector, frameinfo, variant.platform, manufacturer,
        encrypted, decrypted, datagramname)
    pinfo.cols.info = frameinfo
end

-- Register as a post-dissector; this will run for every frame.
register_postdissector(PowerBoxDissector)
