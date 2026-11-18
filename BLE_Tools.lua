-- BLE_Tools.lua
--
-- Shared helper for the post-dissectors (MouldKing, CaDA, CaDA HS, PowerBox).
--
-- Problem: the dissectors used to read the advertising data at absolute frame offsets
-- that were only valid for the 17 byte header of the Nordic nRF Sniffer (DLT 272).
-- Other captures (DLT 256 with a 10 byte pseudo header, DLT 251 without any header)
-- put the BLE link layer (LL) packet at a different offset.
--
-- Solution: ask Wireshark where its "btle" dissector found the LL packet (the field
-- starts at the access address) and hand the dissectors that packet as a Tvb of its
-- own. All offsets in the dissectors are then relative to the access address.
--
-- LL packet layout used by the dissectors:
--   0..3   access address (little endian)
--   4      PDU header byte 0 (type, flags)
--   5      PDU header byte 1 (payload length = AdvA(6) + AdvData)
--   6..11  advertiser address AdvA
--   12..   advertising data
--   then   CRC (3 bytes), not needed here
--
-- Besides getLinkLayer() the module holds the small helpers all dissectors share, so that the
-- dissector files only contain data (variant tables) and no copy-pasted code:
--   matches()          check a list of {offset, byte} pairs against the advertising data
--   hex()              format bytes as " 7b a7 80"
--   describe()         build the "Cmd[ad] ID[7b a7] 80 80" text of a decrypted datagram
--   addPayloadTrees()  add the "Payload" and "decrypted" subtrees to the packet tree
--   newDatagramFields() / addHidden()  ProtoFields that make the decoded values filterable
--
-- Needs Lua 5.3 or newer (Wireshark 4.4 or newer), like the other modules of this repository.

local BleTools = {}

-- Access address of every advertising channel packet.
BleTools.ADV_ACCESS_ADDRESS = 0x8E89BED6

-- Offset of the first advertising data byte relative to the access address.
BleTools.ADV_DATA_OFFSET = 12

-- Smallest LL packet that can hold AA(4) + header(2) + AdvA(6).
local MIN_LL_LENGTH = BleTools.ADV_DATA_OFFSET

-- Field.new may only be called while the script is loaded (not inside a dissector
-- function), therefore it is created once here. Because the module is cached by
-- require(), every dissector shares this single field extractor. Creating the
-- extractor also makes Wireshark/tshark populate the "btle" field for post-dissectors.
local f_btle = Field.new("btle")

--- Locate the BLE advertising LL packet of the current frame.
-- The packet is taken from the "btle" field itself (fi.range:tvb()), NOT from the
-- frame offset: fi.offset / fi.source are intentionally not used because the field may
-- live in another data source than the post-dissector buffer.
-- @return Tvb starting at the access address and the advertising data length
--         (AdvData only, without AdvA and CRC), or nil when the frame is not a
--         valid, complete advertising packet.
function BleTools.getLinkLayer()
    local fi = f_btle()                 -- first btle field of this frame, nil if absent
    if not fi then
        return nil
    end

    -- Re-base the field range to its own Tvb; guard against API errors.
    local ok, ll = pcall(function() return fi.range:tvb() end)
    if not ok or not ll then
        return nil
    end

    if ll:len() < MIN_LL_LENGTH then
        return nil
    end

    -- Only advertising channel packets are of interest.
    if ll(0, 4):le_uint() ~= BleTools.ADV_ACCESS_ADDRESS then
        return nil
    end

    -- PDU length counts AdvA (6 bytes) and the advertising data.
    local advLen = ll(5, 1):uint() - 6
    if advLen < 0 or ll:len() < BleTools.ADV_DATA_OFFSET + advLen then
        return nil                      -- bogus or truncated packet
    end

    return ll, advLen
end

--- Check the advertising data against a byte pattern.
-- The pattern lists only the bytes that identify a device; bytes that vary (device id,
-- payload, ...) are simply not listed ("don't care").
-- @param ll      Tvb of the LL packet as returned by getLinkLayer()
-- @param base    offset the pattern offsets are relative to (usually ADV_DATA_OFFSET; a
--                "virtual" base is fine for variants whose AD structures start earlier)
-- @param pattern list of {offset, expectedByte} pairs
-- @return true when every byte matches; false on the first mismatch or when an offset lies
--         outside of the packet (no Lua error is raised)
function BleTools.matches(ll, base, pattern)
    for _, entry in ipairs(pattern) do
        local offset = base + entry[1]
        -- A pattern longer than the packet can never match; do not raise "out of bounds".
        if offset < 0 or offset >= ll:len() then
            return false
        end
        if ll(offset, 1):uint() ~= entry[2] then
            return false
        end
    end
    return true
end

--- Format a range of bytes as lower case hex, every byte preceded by a space.
-- @param bytes ByteArray (0 based get_index)
-- @param first index of the first byte
-- @param last  index of the last byte (inclusive)
-- @return text like " 7b a7 80"; empty string when last < first
function BleTools.hex(bytes, first, last)
    local text = ""
    for index = first, last do
        text = text .. string.format(" %02x", bytes:get_index(index))
    end
    return text
end

--- Describe a decrypted datagram: "Cmd[ad] ID[7b a7]" plus optional data bytes.
-- Layout of all MouldKing / PowerBox datagrams: byte 0 command, bytes 1..2 device id,
-- bytes 3.. data (the last byte is a checksum that is not shown).
-- @param bytes      decrypted datagram (ByteArray)
-- @param dataLength number of data bytes (starting at byte 3) to append; 0 = id only (Connect)
-- @return text like "Cmd[66] ID[7b a7] 80 80 80 80"
function BleTools.describe(bytes, dataLength)
    local text = string.format("Cmd[%02x] ID[%02x%s]",
        bytes:get_index(0), bytes:get_index(1), BleTools.hex(bytes, 2, 2))
    if dataLength > 0 then
        text = text .. BleTools.hex(bytes, 3, 2 + dataLength)
    end
    return text
end

--- Create the ProtoFields shared by the decrypting dissectors (MouldKing, PowerBox).
-- The fields make the decoded values filterable (e.g. `mouldking.cmd == 0x66`) and available to
-- `tshark -T fields -e`. They are added to the tree as hidden items (or with the unchanged
-- label text) so the visible packet tree does not change.
-- @param abbrev abbreviation prefix of the dissector's Proto, e.g. "mouldking"
-- @return fields table (platform, manufacturer, payload, datagram, cmd, id, data) and
--         the same fields as a list for `Proto.fields = list`
function BleTools.newDatagramFields(abbrev)
    local fields = {
        platform = ProtoField.string(abbrev .. ".platform", "Platform"),
        manufacturer = ProtoField.string(abbrev .. ".manufacturer", "Manufacturer"),
        payload = ProtoField.bytes(abbrev .. ".payload", "Encrypted payload"),
        datagram = ProtoField.string(abbrev .. ".datagram", "Datagram"),
        cmd = ProtoField.uint8(abbrev .. ".cmd", "Command", base.HEX),
        id = ProtoField.uint16(abbrev .. ".id", "Device id", base.HEX),
        data = ProtoField.bytes(abbrev .. ".data", "Data"),
    }
    local list = { fields.platform, fields.manufacturer, fields.payload, fields.datagram,
                   fields.cmd, fields.id, fields.data }
    return fields, list
end

--- Add a ProtoField item that is filterable but not visible in the packet details.
-- @param subtree tree item to add to
-- @param field   ProtoField
-- @param range   TvbRange the item covers
-- @param value   optional value (required for string fields)
function BleTools.addHidden(subtree, field, range, value)
    local item
    if value ~= nil then
        item = subtree:add(field, range, value)
    else
        item = subtree:add(field, range)
    end
    item:set_hidden()
end

--- Add the two subtrees every decrypting dissector shows for a frame.
--   "<platform> - <manufacturer> - Payload"    : the raw (encrypted) payload and its length
--   "<platform> - <manufacturer> - decrypted"  : the decrypted datagram, its name and length
-- Does nothing when there is no tree (Wireshark only needs the Info column then) or when
-- the payload could not be decrypted.
-- @param tree         tree passed to the dissector function (may be nil)
-- @param proto        Proto object of the calling dissector
-- @param frameinfo    text used as name of the synthetic data sources
-- @param platform     "Android", "iOS", "Windows"
-- @param manufacturer "MouldKing", "JIE-STAR", ...
-- @param encrypted    raw payload as ByteArray
-- @param decrypted    decrypted datagram as ByteArray (nil when decryption failed)
-- @param datagramname name of the datagram, e.g. "MK4.0/MK5.0 Connect - Cmd[ad] ID[7b a7]"
-- @param fields       optional table from newDatagramFields(): the values are then also added as
--                     filterable fields (hidden, except the datagram line which keeps its text)
function BleTools.addPayloadTrees(tree, proto, frameinfo, platform, manufacturer, encrypted, decrypted, datagramname, fields)
    if not (tree and decrypted) then
        return
    end
    local prefix = platform .. " - " .. manufacturer .. " - "

    -- The ByteArray data sources make the bytes visible (and selectable) in the hex view.
    local tvb1 = ByteArray.tvb(encrypted, frameinfo)
    local subtree1 = tree:add(proto, tvb1(), prefix .. "Payload")
    subtree1:add(tvb1(), "Len: " .. tvb1():len())

    local tvb2 = ByteArray.tvb(decrypted, frameinfo)
    local subtree2 = tree:add(proto, tvb2(), prefix .. "decrypted")
    local line = datagramname .. "-Datagram - Len: " .. tvb2():len()
    if not fields then
        subtree2:add(tvb2(), line)
        return
    end

    -- Same visible text as without fields, but the line carries the datagram name as field.
    subtree2:add(fields.datagram, tvb2(), datagramname, line)
    BleTools.addHidden(subtree1, fields.payload, tvb1())
    BleTools.addHidden(subtree2, fields.platform, tvb2(), platform)
    BleTools.addHidden(subtree2, fields.manufacturer, tvb2(), manufacturer)
    BleTools.addHidden(subtree2, fields.cmd, tvb2(0, 1))
    BleTools.addHidden(subtree2, fields.id, tvb2(1, 2))
    if tvb2():len() > 4 then
        BleTools.addHidden(subtree2, fields.data, tvb2(3, tvb2():len() - 4))
    end
end

return BleTools
