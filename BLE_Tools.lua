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
-- Plain Lua 5.1 - 5.4 compatible (Wireshark 4.2 embeds Lua 5.2): no bit operators.

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

return BleTools
