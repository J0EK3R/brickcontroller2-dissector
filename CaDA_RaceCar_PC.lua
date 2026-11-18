-- CaDA_RaceCar_PC.lua
--
-- Wireshark post-dissector for the Bluetooth LE advertising datagrams of the CaDA RaceCar
-- "PC" type (Android and iOS app) and of the response frames of the car. The control
-- datagrams are decrypted twice: Crypt_Tools removes the RF whitening, CaDA_Tools reverses
-- the second layer of the 8 byte control block.
--
-- Structure of this file: preamble -> constants/tables -> helpers -> dissector -> registration.

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
local CaDATools = require("CaDA_Tools")

-- Protocol object of this post-dissector (used as the owner of the tree items).
local CaDADissector = Proto("CaDA", "Global Frame Analyzer for Bluetooth LE from CaDA")

-- Decryption parameters of the CaDA datagrams.
local SEED = { 0x43, 0x41, 0x52 }
local CTX_VALUE_1 = 0x3f
local CTX_VALUE_2 = 0x26
local HEADER_LENGTH = 3         -- bytes of the decrypted header
local DATA_LENGTH = 16          -- bytes of the decrypted datagram
local CONTROL_BLOCK_OFFSET = 7  -- the 8 byte block CaDA_Tools decrypts starts behind byte 7
local MANUFACTURER = "CaDA"

-- Offsets are relative to the first advertising data byte.
local ADV_DATA = BleTools.ADV_DATA_OFFSET

-- Device response (the car answers the app): the advertising data holds the unencrypted
-- 16 byte response datagram from offset 7 on.
local RESPONSE_ADV_LEN = 23
local RESPONSE_PATTERN = {
    { 3, 0x13 },    -- AD length: 19
    { 4, 0xff },    -- AD type: Manufacturer Specific (0xff)
    { 5, 0xf0 },    -- company id 0xfff0
    { 6, 0xff },
    { 7, 0x75 },    -- CaDA identifier
    -- offset 8: flag byte, checked separately (bit 0x40 must be set)
    -- offset 9..22: device id 0x31f5e5, app address 0x7929cb, zeroes - not checked
}
local RESPONSE_RAW_OFFSET = ADV_DATA + 7
local RESPONSE_RAW_LENGTH = 16

-- Variant table of the encrypted app datagrams (Android / iOS), tried in this order.
--   platform       shown in the Info column
--   advLen         exact length of the advertising data
--   pattern        identifying bytes as {offset, value} pairs (everything else is "don't care")
--   rawOffset      where the encrypted payload starts
--   rawLength      length of the encrypted payload
--   headerOffset   position of the header in the whitening sequence (see Crypt_Tools)
local VARIANTS = {
    {
        platform = "Android",
        advLen = 31,
        pattern = {
            { 3, 0x1b },    -- AD length: 27
            { 4, 0xff },    -- AD type: Manufacturer Specific (0xff)
            { 5, 0x00 },    -- company id 0xc200
            { 6, 0xc2 },
            { 7, 0xee },    -- CaDA identifier (first bytes of the encrypted payload)
            { 8, 0x1b },
            { 9, 0xc8 },
            { 10, 0xaf },
            { 11, 0x9f },
            { 12, 0x3c },
        },
        rawOffset = ADV_DATA + 7,
        rawLength = 24,
        headerOffset = 15,
    },
    {
        platform = "iOS",
        advLen = 31,
        pattern = {
            { 3, 0x1b },    -- AD length: 27
            { 4, 0x03 },    -- AD type: Complete List of 16-bit Service Class UUIDs (0x03)
            { 5, 0xc0 },    -- identifier 0xc03d (first bytes of the encrypted payload)
            { 6, 0x3d },
            { 7, 0xca },
            { 8, 0x66 },
            { 9, 0x6d },
            { 10, 0x32 },
            -- offset 11..31: rest of the encrypted payload, not checked
        },
        rawOffset = ADV_DATA + 5,
        rawLength = 24,
        headerOffset = 13,
    },
}

--- Tell whether the frame is a device response.
-- @return true for a device response frame
local function isDeviceResponse(ll, advLen)
    return advLen == RESPONSE_ADV_LEN
        and BleTools.matches(ll, ADV_DATA, RESPONSE_PATTERN)
        and (ll(ADV_DATA + 8, 1):uint() & 0x40) ~= 0        -- flag byte: bit 0x40 set
end

--- Find the variant row whose identifier matches the advertising data.
-- @return the matching row of VARIANTS or nil
local function findVariant(ll, advLen)
    for _, variant in ipairs(VARIANTS) do
        if advLen == variant.advLen and BleTools.matches(ll, ADV_DATA, variant.pattern) then
            return variant
        end
    end
    return nil
end

--- Add the fields every CaDA datagram starts with to a subtree.
-- Layout: byte 0 id, byte 1 command, bytes 2..4 device address, bytes 5..7 app address.
-- @param subtree tree item to add the lines to
-- @param tvb     Tvb of the decrypted datagram
local function addCommonFields(subtree, tvb)
    subtree:add(tvb(0, 1), "Id: 0x" .. tvb(0, 1))
    subtree:add(tvb(1, 1), "Cmd: 0x" .. tvb(1, 1))
    subtree:add(tvb(2, 3), "DeviceAddr: 0x" .. tvb(2, 3))
    subtree:add(tvb(5, 3), "AppAddr: 0x" .. tvb(5, 3))
end

--- Show a device response frame (Info column and packet tree).
local function dissectResponse(ll, pinfo, tree)
    local datagramname = "Response"
    local frameinfo = "Device - " .. MANUFACTURER .. " - " .. datagramname
    pinfo.cols.info = frameinfo

    if tree then
        local tvb = ByteArray.tvb(ll(RESPONSE_RAW_OFFSET, RESPONSE_RAW_LENGTH):bytes(), frameinfo)
        local subtree = tree:add(CaDADissector, tvb(), frameinfo)
        subtree:add(tvb(), datagramname .. " - Len: " .. tvb():len())
        addCommonFields(subtree, tvb)
    end
end

--- Show an encrypted app datagram (Connect / Control / other) of the given variant.
local function dissectDatagram(ll, variant, pinfo, tree)
    -- Decrypt the payload.
    local encrypted = ll(variant.rawOffset, variant.rawLength):bytes()
    local decrypted = CryptTools.DecryptRfPayload(SEED, HEADER_LENGTH, DATA_LENGTH,
        variant.headerOffset, CTX_VALUE_1, CTX_VALUE_2, encrypted)

    -- Datagrams start with the id 0x75; without it the content is not interpreted.
    local datagramname = "Data"
    if decrypted:get_index(0) == 0x75 then
        local command = decrypted:get_index(1)
        if command == 0x10 then
            datagramname = "Connect"
        elseif command == 0x13 then
            datagramname = "Control"
            -- The control block carries a second encryption layer.
            CaDATools.Decrypt(decrypted, CONTROL_BLOCK_OFFSET)
        else
            datagramname = "unknown"
        end
    end

    local frameinfo = variant.platform .. " - " .. MANUFACTURER .. " - " .. datagramname
    pinfo.cols.info = frameinfo

    if tree then
        local tvb1 = ByteArray.tvb(encrypted, frameinfo)
        local subtree1 = tree:add(CaDADissector, tvb1(), variant.platform .. " - " .. MANUFACTURER .. " - Payload")
        subtree1:add(tvb1(), "Len: " .. tvb1():len())

        local tvb2 = ByteArray.tvb(decrypted, frameinfo)
        local subtree2 = tree:add(CaDADissector, tvb2(), frameinfo)
        subtree2:add(tvb2(), datagramname .. " - Len: " .. tvb2():len())
        addCommonFields(subtree2, tvb2)
        -- Random value and channel bytes are shown for every app datagram (not only for Control).
        subtree2:add(tvb2(8, 2), "Random: 0x" .. tvb2(8, 2))
        subtree2:add(tvb2(10, 1), "Channel 1: 0x" .. tvb2(10, 1))
        subtree2:add(tvb2(11, 1), "Channel 2: 0x" .. tvb2(11, 1))
        subtree2:add(tvb2(12, 1), "Channel 3: 0x" .. tvb2(12, 1))
    end
end

--- Post-dissector function, called by Wireshark for every frame.
-- Leaves frames alone that are not CaDA PC advertising packets (returns 0).
function CaDADissector.dissector(buffer, pinfo, tree)
    -- Locate the BLE link layer packet (independent of the capture link type);
    -- ll starts at the access address, advLen is the length of the advertising data.
    local ll, advLen = BleTools.getLinkLayer()
    if not ll then
        return 0
    end

    if isDeviceResponse(ll, advLen) then
        dissectResponse(ll, pinfo, tree)
        return
    end

    local variant = findVariant(ll, advLen)
    if not variant then
        return 0
    end
    dissectDatagram(ll, variant, pinfo, tree)
end

-- Register as a post-dissector; this will run for every frame.
register_postdissector(CaDADissector)
