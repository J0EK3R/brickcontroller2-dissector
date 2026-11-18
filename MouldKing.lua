-- MouldKing.lua
--
-- Wireshark post-dissector for the Bluetooth LE advertising datagrams of MouldKing hubs
-- (MK2.0 .. MK8.0, MK4.0/5.0, MK6.0, 4P Blade, Mecanum) and of the JIE-STAR clones
-- (4CH / 8CH). The advertising payload is decrypted with Crypt_Tools and shown in the Info
-- column and in the packet tree.
--
-- Structure of this file: preamble -> constants/tables -> helpers -> dissector -> registration.
-- Everything device specific is data:
--   * VARIANTS - how the advertising packet of an app platform looks like and is decrypted
--   * COMMANDS - what the first byte of the decrypted datagram means
-- A new device is normally one more row of COMMANDS, a new app/platform one more row of VARIANTS.

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
local MouldKingDissector = Proto("MouldKing", "Global Frame Analyzer for Bluetooth LE from MouldKing")

-- Decryption parameters. MouldKing and JieStar share seed and first whitening value, only the
-- second whitening value differs (CTX_VALUE_2_*).
local SEED = { 0xC1, 0xC2, 0xC3, 0xC4, 0xC5 }
local CTX_VALUE_1 = 0x3f
local CTX_VALUE_2_MK = 0x25
local CTX_VALUE_2_JS_EE = 0x26
local CTX_VALUE_2_JS_6F = 0x27
local HEADER_LENGTH = 3     -- bytes of the decrypted header (command + 2 byte device id)

-- Offsets in the variant rows are relative to the first advertising data byte.
local ADV_DATA = BleTools.ADV_DATA_OFFSET

-- Variant table, one row per app platform / hub family, tried in this order.
--   platform       shown in the Info column
--   manufacturer   used when the command does not name one (see COMMANDS)
--   advLen         exact length of the advertising data
--   pattern        identifying bytes as {offset, value} pairs (everything else is "don't care")
--   rawOffset      where the encrypted payload starts
--   rawLength      number of bytes read from there (more than the payload; only the first
--                  18 / 20 bytes are used by the decryption)
--   headerOffset   position of the header in the whitening sequence (see Crypt_Tools)
--   fillOffset     position of two "fill" bytes behind an 8 byte payload; a 10 byte payload
--                  overwrites them
--   fill           the two values the fill bytes have behind an 8 byte payload
--   ctx2           second whitening value
--   fourChannel    name of JIE-STAR 4CH hubs seen with this identifier (nil: none known)
local VARIANTS = {
    {
        platform = "Android",
        manufacturer = "MouldKing",
        advLen = 31,
        pattern = {
            { 3, 0x1b },    -- AD length: 27
            { 4, 0xff },    -- AD type: Manufacturer Specific (0xff)
            { 5, 0xf0 },    -- company id 0xfff0
            { 6, 0xff },
            { 7, 0x6d },    -- MouldKing identifier (first bytes of the encrypted payload)
            { 8, 0xb6 },
            { 9, 0x43 },
            { 10, 0xcf },
            { 11, 0x7e },
            { 12, 0x8f },
            { 13, 0x47 },
            { 14, 0x11 },
        },
        rawOffset = ADV_DATA + 7,
        rawLength = 25,
        headerOffset = 15,
        fillOffset = ADV_DATA + 25,
        fill = { 0x13, 0x14 },
        ctx2 = CTX_VALUE_2_MK,
        fourChannel = "JIE-STAR 4CH[1]",
    },
    {
        -- TODO: the payload length of the iOS app is unverified and needs a real iOS capture.
        -- Only 18 bytes follow the identifier (advLen 23) but 26 bytes are read, so the frame
        -- does not fit and is skipped (see the bounds check in the dissector).
        platform = "iOS",
        manufacturer = "MouldKing",
        advLen = 23,
        pattern = {
            { 5, 0xf9 },    -- identifier (first bytes of the encrypted payload)
            { 6, 0x08 },
            { 7, 0x49 },
            { 8, 0x22 },
            { 9, 0x47 },
            { 10, 0xba },
            { 11, 0xc4 },
            { 12, 0xbc },
        },
        rawOffset = ADV_DATA + 5,
        rawLength = 26,
        headerOffset = 13,
        fillOffset = ADV_DATA + 23,
        fill = { 0x12, 0x13 },
        ctx2 = CTX_VALUE_2_MK,
        fourChannel = nil,
    },
    {
        platform = "Android",
        manufacturer = "MouldKing",
        advLen = 31,
        pattern = {
            { 3, 0x1b },    -- AD length: 27
            { 4, 0xff },    -- AD type: Manufacturer Specific (0xff)
            { 5, 0xf0 },    -- company id 0xfff0
            { 6, 0xff },
            { 7, 0xee },    -- JieStar identifier (first bytes of the encrypted payload)
            { 8, 0x1b },
            { 9, 0xc8 },
            { 10, 0x46 },
            { 11, 0x3e },
            { 12, 0x3d },
            { 13, 0xfb },
            { 14, 0xd2 },
        },
        rawOffset = ADV_DATA + 7,
        rawLength = 25,
        headerOffset = 15,
        fillOffset = ADV_DATA + 25,
        fill = { 0x13, 0x14 },
        ctx2 = CTX_VALUE_2_JS_EE,
        fourChannel = "JIE-STAR 4CH[2]",
    },
    {
        platform = "Android",
        manufacturer = "JieStarRaw",
        advLen = 31,
        pattern = {
            { 3, 0x1b },    -- AD length: 27
            { 4, 0xff },    -- AD type: Manufacturer Specific (0xff)
            { 5, 0xf0 },    -- company id 0xfff0
            { 6, 0xff },
            { 7, 0x6f },    -- JieStar identifier (first bytes of the encrypted payload)
            { 8, 0x7f },
            { 9, 0xb1 },
            { 10, 0xc1 },
            { 11, 0x01 },
            { 12, 0x53 },
            { 13, 0x6f },
            { 14, 0x6c },
        },
        rawOffset = ADV_DATA + 7,
        rawLength = 25,
        headerOffset = 15,
        fillOffset = ADV_DATA + 25,
        fill = { 0x13, 0x14 },
        ctx2 = CTX_VALUE_2_JS_6F,
        fourChannel = "JIE-STAR 4CH[3]",
    },
}

-- Datagram sizes: "short" datagrams have 8 bytes, "long" ones 10 bytes.
local SHORT_LENGTH = 8
local LONG_LENGTH = 10

--- Resolve the JIE-STAR "a4" connect datagram; the third byte tells the hub type.
-- @return manufacturer, name, kind - or nil when this variant has no such hub (the caller then
--         keeps the generic "<n>-Byte Payload - Command: 0x.. - Length: n" name)
local function resolveJieStarConnect(variant, datagram)
    local third = datagram:get_index(3)
    if third == 0x00 then
        -- JIE-STAR 8CH   a4 1d 74 00 00 00 00 5b
        return "JIE-STAR", "JIE-STAR 8CH Connect", "connect"
    elseif third == 0x80 then
        -- JIE-STAR 4CH   a4 1d 74 80 80 80 80 5b
        if variant.fourChannel then
            return "JIE-STAR", variant.fourChannel .. " Connect", "connect"
        end
        return nil
    end
    return "JIE-STAR", "JIE-STAR unknown", "connect"
end

--- Resolve the JIE-STAR 4CH "40" command datagram (the 4CH flavour depends on the variant).
-- JIE-STAR 4CH   40 1d 74 80 80 80 80 bf
-- @return manufacturer, name, kind - or nil when this variant has no 4CH hub (see above)
local function resolveJieStar4chCommand(variant)
    if variant.fourChannel then
        return "JIE-STAR", variant.fourChannel .. " Command", "command"
    end
    return nil
end

-- Command table, keyed by the first byte of the decrypted datagram. A row is only used when the
-- datagram has exactly `length` bytes (8 or 10). Rows have either static fields
--   manufacturer, name, kind ("connect": show only the device id; "command": also show the
--   data bytes 3 .. length - 2)
-- or a `resolve(variant, datagram)` function returning manufacturer, name, kind (see above).
-- The comment of a row is a sample datagram: command, device id (2 bytes), data, checksum.
-- Commands not listed here (or with another length) are shown as "Unknown".
local COMMANDS = {
    -- MK2.0, MK3.0, MK4.0D, MK8.0
    [0xaa] = { length = SHORT_LENGTH, manufacturer = "MouldKing", kind = "connect",
               name = "MK2.0/MK3.0/MK4.0D/MK8.0 Connect" },     -- aa 7b a7 00 00 00 00 55
    [0x66] = { length = SHORT_LENGTH, manufacturer = "MouldKing", kind = "command",
               name = "MK2.0/MK3.0/MK4.0D/MK8.0 Command" },     -- 66 7b a7 80 80 80 80 99
    [0x77] = { length = SHORT_LENGTH, manufacturer = "MouldKing", kind = "command",
               name = "MK4.0D Command" },                       -- 77 7b a7 00 00 00 00 88

    -- MK3.8
    [0xb1] = { length = SHORT_LENGTH, manufacturer = "MouldKing", kind = "connect",
               name = "MK3.8 Connect" },                        -- b1 7b a7 80 80 80 4f c1
    [0x81] = { length = LONG_LENGTH, manufacturer = "MouldKing", kind = "command",
               name = "MK3.8 Command" },                        -- 81 7b 00 99 99 99 99 99 99 c2

    -- MK4.0, MK5.0, 4P Blade 4.0
    [0xad] = { length = SHORT_LENGTH, manufacturer = "MouldKing", kind = "connect",
               name = "MK4.0/MK5.0 Connect" },                  -- ad 7b a7 80 80 80 4f 52
    [0x7d] = { length = LONG_LENGTH, manufacturer = "MouldKing", kind = "command",
               name = "MK4.0/MK5.0 Command" },                  -- MK4.0 7d 7b a7 88 88 88 88 88 88 82
                                                                -- MK5.0 7d 7b a7 00 00 80 80 80 80 82

    -- MK6.0, Mecanum, 4P Blade 6.0
    [0x6d] = { length = SHORT_LENGTH, manufacturer = "MouldKing", kind = "connect",
               name = "MK6.0 Connect" },                        -- 6d 7b a7 80 80 80 80 92
    [0x61] = { length = LONG_LENGTH, manufacturer = "MouldKing", kind = "command",
               name = "MK6.0[1] Command" },                     -- 61 7b a7 80 80 80 80 80 80 9e
    [0x62] = { length = LONG_LENGTH, manufacturer = "MouldKing", kind = "command",
               name = "MK6.0[2] Command" },                     -- 62 7b a7 80 80 01 80 80 80 9d
    [0x63] = { length = LONG_LENGTH, manufacturer = "MouldKing", kind = "command",
               name = "MK6.0[3] Command" },                     -- 63 7b a7 80 80 80 80 80 80 9c

    -- JIE-STAR
    [0xa4] = { length = SHORT_LENGTH, resolve = resolveJieStarConnect },
    [0x40] = { length = SHORT_LENGTH, resolve = resolveJieStar4chCommand },
    [0x41] = { length = SHORT_LENGTH, manufacturer = "JIE-STAR", kind = "command",
               name = "JIE-STAR 8CH[1] Command" },              -- 41 34 17 00 00 00 00 bf
    [0x42] = { length = SHORT_LENGTH, manufacturer = "JIE-STAR", kind = "command",
               name = "JIE-STAR 8CH[2] Command" },              -- 42 34 17 00 00 00 00 be
    [0x43] = { length = SHORT_LENGTH, manufacturer = "JIE-STAR", kind = "command",
               name = "JIE-STAR 8CH[3] Command" },              -- 43 34 17 00 00 00 00 bd
}

--- Find the variant row whose identifier matches the advertising data.
-- @param ll     Tvb of the LL packet
-- @param advLen length of the advertising data
-- @return the matching row of VARIANTS or nil
local function findVariant(ll, advLen)
    for _, variant in ipairs(VARIANTS) do
        if advLen == variant.advLen and BleTools.matches(ll, ADV_DATA, variant.pattern) then
            return variant
        end
    end
    return nil
end

--- Tell whether the payload is the short (8 byte) or long (10 byte) datagram.
-- Behind a short payload two known fill bytes follow, a long payload overwrites them.
-- @return true for the short datagram
local function isShortDatagram(ll, variant)
    return BleTools.matches(ll, variant.fillOffset, { { 0, variant.fill[1] }, { 1, variant.fill[2] } })
end

--- Build manufacturer and datagram name for a decrypted datagram.
-- @param variant   row of VARIANTS
-- @param datagram  decrypted datagram (ByteArray)
-- @param sizeName  "8-Byte Payload" or "10-Byte Payload"
-- @return manufacturer, datagramname
local function describeDatagram(variant, datagram, sizeName)
    local command = datagram:get_index(0)
    local length = datagram:len()

    -- Default (also used by the iOS variant for the JIE-STAR commands, which it does not
    -- know): only the size, the command byte and the length.
    local manufacturer = variant.manufacturer
    local name = sizeName .. " - Command: " .. string.format("0x%02x", command) .. " - Length: " .. length
    local kind = nil

    local row = COMMANDS[command]
    if row and row.length == length then
        local rowManufacturer, rowName, rowKind
        if row.resolve then
            rowManufacturer, rowName, rowKind = row.resolve(variant, datagram)
        else
            rowManufacturer, rowName, rowKind = row.manufacturer, row.name, row.kind
        end
        if rowName then
            manufacturer = rowManufacturer
            name = rowName
            kind = rowKind
        else
            return manufacturer, name           -- row exists but not for this variant
        end
    else
        manufacturer = "Unknown"
        name = "Unknown"
        kind = "connect"                         -- unknown: show Cmd and ID only
    end

    -- Connect shows only the id, a command also the data bytes (length - 4 of them).
    local dataLength = (kind == "command") and (length - 4) or 0
    return manufacturer, name .. " - " .. BleTools.describe(datagram, dataLength)
end

--- Post-dissector function, called by Wireshark for every frame.
-- Leaves frames alone that are not MouldKing/JieStar advertising packets (returns 0).
function MouldKingDissector.dissector(buffer, pinfo, tree)
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

    -- Bounds check: the range read below and the fill bytes must lie inside the packet, otherwise
    -- Wireshark raises "Range is out of bounds" (this is what the iOS variant used to do).
    if variant.rawOffset + variant.rawLength > ll:len() or variant.fillOffset + 2 > ll:len() then
        return 0
    end

    local datagramSize = isShortDatagram(ll, variant) and SHORT_LENGTH or LONG_LENGTH
    local sizeName = datagramSize .. "-Byte Payload"

    -- Decrypt the payload.
    local encrypted = ll(variant.rawOffset, variant.rawLength):bytes()
    local decrypted = CryptTools.DecryptRfPayload(SEED, HEADER_LENGTH, datagramSize,
        variant.headerOffset, CTX_VALUE_1, variant.ctx2, encrypted)

    local manufacturer = variant.manufacturer
    local datagramname
    if decrypted then
        manufacturer, datagramname = describeDatagram(variant, decrypted, sizeName)
    else
        datagramname = "Decryption failed"
    end

    local frameinfo = variant.platform .. " - " .. manufacturer .. " - " .. datagramname
    BleTools.addPayloadTrees(tree, MouldKingDissector, frameinfo, variant.platform, manufacturer,
        encrypted, decrypted, datagramname)
    pinfo.cols.info = frameinfo
end

-- Register as a post-dissector; this will run for every frame.
register_postdissector(MouldKingDissector)
