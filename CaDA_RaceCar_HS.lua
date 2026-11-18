-- CaDA_RaceCar_HS.lua
--
-- Wireshark post-dissector for the Bluetooth LE advertising datagrams of the CaDA RaceCar
-- "HS" type (Android and iOS app) and of the response frames of the car. The HS datagrams are
-- NOT encrypted; they are decoded directly.
--
-- Datagram layout (16 bytes starting at the command byte):
--   0      command: 0xaa = Connect, 0xbb = Control
--   1..2   header 0x11 0x11
--   3..4   device id (little endian)
--   5..6   app id (little endian)
--   7      throttle   (Control)
--   8      steering   (Control)
--   9      lights     (Control)
--   10     offset     (Control) - value the throttle/steering bytes are XORed with
--   11     sequence id
--   12..15 footer 0xcc 0xb8 0x92 0xb0 (0xa0 as last byte for Connect)
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

-- Protocol object of this post-dissector (used as the owner of the tree items).
local CaDADissector = Proto("CaDA_HS", "Global Frame Analyzer for Bluetooth LE from CaDA - Type HS")

local MANUFACTURER = "CaDA HS"
local COMMAND_CONNECT = 0xaa
local COMMAND_CONTROL = 0xbb

-- Offsets are relative to the first advertising data byte.
local ADV_DATA = BleTools.ADV_DATA_OFFSET

-- Device response (the car answers the app): 14 bytes starting at offset 4.
local RESPONSE_ADV_LEN = 31
local RESPONSE_PATTERN = {
    { 0, 0x11 },    -- AD length: 17
    { 1, 0xff },    -- AD type: Manufacturer Specific (0xff)
    { 2, 0xaa },    -- company id 0x11aa
    { 3, 0x11 },
    { 4, 0x11 },    -- CaDA identifier
}
local RESPONSE_RAW_OFFSET = ADV_DATA + 4
local RESPONSE_RAW_LENGTH = 14

-- Variant table of the app datagrams (Android / iOS), tried in this order.
--   platform   shown in the Info column
--   advLen     exact length of the advertising data
--   pattern    identifying bytes as {offset, value} pairs (everything else is "don't care")
--   rawOffset  where the 16 byte datagram starts
--   rawLength  length of the datagram
local VARIANTS = {
    {
        platform = "Android",
        advLen = 23,
        pattern = {
            { 3, 0x13 },    -- AD length: 19
            { 4, 0xff },    -- AD type: Manufacturer Specific (0xff)
            { 5, 0x00 },    -- company id 0xc200
            { 6, 0xc2 },
            -- offset 7: command (0xbb control or 0xaa connect), not checked
            { 8, 0x11 },    -- header 0x11 0x11
            { 9, 0x11 },
            -- offset 10..13: device id and app id, not checked
            -- offset 14..18: throttle, steering, lights, offset, sequence id, not checked
            { 19, 0xcc },   -- footer 0xcc 0xb8 0x92
            { 20, 0xb8 },
            { 21, 0x92 },
            -- offset 22: last footer byte (0xb0 control or 0xa0 connect), not checked
        },
        rawOffset = ADV_DATA + 7,
        rawLength = 16,
    },
    {
        platform = "iOS",
        advLen = 31,
        pattern = {
            { 3, 0x1b },    -- AD length: 27
            { 4, 0x03 },    -- AD type: Complete List of 16-bit Service Class UUIDs (0x03)
            { 5, 0xc0 },    -- CaDA identifier 0xc000
            { 6, 0x00 },
            -- offset 7: command (0xbb control or 0xaa connect), not checked
            { 8, 0x11 },    -- header 0x11 0x11
            { 9, 0x11 },
            -- offset 10..18: device id, app id, throttle .. sequence id, not checked
            { 19, 0xcc },   -- footer 0xcc 0xb8 0x92
            { 20, 0xb8 },
            { 21, 0x92 },
            -- offset 22..30: last footer byte and trailing bytes, not checked
        },
        rawOffset = ADV_DATA + 7,
        rawLength = 16,
    },
}

--- Tell whether the frame is a device response.
local function isDeviceResponse(ll, advLen)
    return advLen == RESPONSE_ADV_LEN and BleTools.matches(ll, ADV_DATA, RESPONSE_PATTERN)
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

--- Decode the control values of a Control datagram.
-- The throttle and steering bytes are XORed with the offset byte; the real value is the
-- result minus 0x80 (throttle: negated, so that "forward" is positive).
-- @param rawdata TvbRange of the 16 byte datagram
-- @return seqIdName, offsetString, throttleString, steeringString, lightsString (display texts like
--         "005[0x05]"; the numeric part is padded to a fixed width)
local function decodeControl(rawdata)
    local seqId = rawdata(11, 1):uint() & 0xff
    local seqIdName = string.format("%03d", seqId) .. "[0x" .. string.format("%02x", seqId) .. "]"

    local offset = rawdata(10, 1):int() & 0xff
    local offsetString = string.format("%03d", offset) .. "[0x" .. string.format("%02x", offset) .. "]"

    local throttle = -(((rawdata(7, 1):int() & 0xff) ~ offset) - 0x80)
    local throttleString = string.format("%4d", throttle) .. "[0x" .. string.format("%02x", throttle & 0xff) .. "]"

    local steering = ((rawdata(8, 1):int() & 0xff) ~ offset) - 0x80
    local steeringString = string.format("%4d", steering) .. "[0x" .. string.format("%02x", steering & 0xff) .. "]"

    -- Lights are shown as the signed byte; a negative value is printed as 64 bit hex ("0xffff...")
    -- like it always was.
    local lights = rawdata(9, 1):int()
    local lightsString = lights .. "[0x" .. string.format("%x", lights) .. "]"

    return seqIdName, offsetString, throttleString, steeringString, lightsString
end

--- Add the packet tree of an app datagram (Connect and Control share it).
-- @param tree         tree passed to the dissector function
-- @param variant      row of VARIANTS
-- @param frameinfo    Info text (also the name of the synthetic data sources)
-- @param datagramname name of the datagram, e.g. "Connect"
-- @param rawdata      TvbRange of the 16 byte datagram
-- @param control      nil for Connect; for Control a table {throttle=, steering=, lights=} with the
--                     display texts of decodeControl(); adds the Throttle/Steering/Lights/Offset lines
local function addTree(tree, variant, frameinfo, datagramname, rawdata, control)
    -- "Payload" subtree with the raw datagram.
    local tvb1 = ByteArray.tvb(rawdata:bytes(), frameinfo)
    local subtree1 = tree:add(CaDADissector, tvb1(), variant.platform .. " - " .. MANUFACTURER .. " - Payload")
    subtree1:add(tvb1(), "Len: " .. tvb1():len())

    -- Second subtree with the decoded fields (the same bytes in a data source of its own).
    local tvb2 = ByteArray.tvb(rawdata:bytes(), frameinfo)
    local subtree2 = tree:add(CaDADissector, tvb2(), frameinfo)
    subtree2:add(tvb2(), datagramname .. " - Len: " .. tvb2():len())
    subtree2:add(tvb2(0, 1), "Cmd: 0x" .. tvb2(0, 1))
    subtree2:add(tvb2(1, 1), "Id: 0x" .. tvb2(1, 1))
    subtree2:add(tvb2(2, 1), "Id: 0x" .. tvb2(2, 1))
    -- Ids are little endian: the bytes are shown swapped.
    subtree2:add(tvb2(3, 2), "Device Id: 0x" .. tvb2(4, 1) .. tvb2(3, 1))
    subtree2:add(tvb2(5, 2), "App Id: 0x" .. tvb2(6, 1) .. tvb2(5, 1))
    if control then
        subtree2:add(tvb2(7, 1), "Throttle: " .. control.throttle)
        subtree2:add(tvb2(8, 1), "Steering: " .. control.steering)
        subtree2:add(tvb2(9, 1), "Lights: " .. control.lights)
        subtree2:add(tvb2(10, 1), "Offset: 0x" .. tvb2(10, 1))
    end
    subtree2:add(tvb2(11, 1), "Sequence Id: 0x" .. tvb2(11, 1))
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
        -- Ids are little endian: the bytes are shown swapped.
        subtree:add(tvb(1, 2), "App Id: 0x" .. tvb(2, 1) .. tvb(1, 1))
        subtree:add(tvb(3, 2), "Device ID: 0x" .. tvb(4, 1) .. tvb(3, 1))
    end
end

--- Show an app datagram of the given variant (only Connect and Control are known).
local function dissectDatagram(ll, variant, pinfo, tree)
    local rawdata = ll(variant.rawOffset, variant.rawLength)
    local command = rawdata(0, 1):uint()

    local datagramname, control
    if command == COMMAND_CONNECT then
        datagramname = "Connect"
    elseif command == COMMAND_CONTROL then
        local seqIdName, offsetString, throttle, steering, lights = decodeControl(rawdata)
        datagramname = "Control Seq=" .. seqIdName .. " O=" .. offsetString ..
            " T=" .. throttle .. " S=" .. steering .. " L=" .. lights
        control = { throttle = throttle, steering = steering, lights = lights }
    else
        return  -- any other command: leave the frame alone (no Info change, no tree)
    end

    local frameinfo = variant.platform .. " - " .. MANUFACTURER .. " - " .. datagramname
    pinfo.cols.info = frameinfo
    if tree then
        addTree(tree, variant, frameinfo, datagramname, rawdata, control)
    end
end

--- Post-dissector function, called by Wireshark for every frame.
-- Leaves frames alone that are not CaDA HS advertising packets (returns 0).
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
