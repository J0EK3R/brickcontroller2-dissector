-- CaDA_Tools.lua
--
-- Second decryption layer of the CaDA "PC" control datagram (after Crypt_Tools has removed
-- the RF whitening). An 8 byte block (the "Control" part of the datagram) is
--   1. substituted byte by byte with a lookup table (SwitchSheet),
--   2. XORed with the first data byte and a constant,
--   3. shuffled: depending on the flag bits of the first byte, nibbles of some bytes are swapped.
-- Decrypt() undoes these steps in reverse order, in place.
--
-- Needs Lua 5.3 or newer: native bit operators (& | ~ << >>) are used, there is no dependency
-- on the "bit" library any more.

local CaDATools = {}

-- Substitution table: the 64 entries are the base values of groups of 4 consecutive values.
-- An original byte `orig` is encrypted to SwitchSheet[orig // 4 + 1] + orig % 4.
local SwitchSheet = {
    0xf4, 0xa8, 0xa0, 0x8c, 0x28, 0xec, 0x44, 0x00,
    0x6c, 0x48, 0x24, 0x98, 0xd4, 0x9c, 0x0c, 0xac,
    0xa4, 0xbc, 0xcc, 0x80, 0x38, 0xe8, 0x5c, 0x1c,
    0x94, 0xb0, 0xc8, 0x54, 0x34, 0x08, 0x74, 0xf0,
    0xdc, 0x14, 0xc4, 0xc0, 0x50, 0x18, 0x64, 0x7c,
    0x70, 0x78, 0x88, 0x90, 0x58, 0x2c, 0xf8, 0x84,
    0x30, 0x68, 0x60, 0x04, 0x40, 0x4c, 0xe0, 0xb8,
    0xd8, 0xfc, 0x20, 0x10, 0xe4, 0x3c, 0xd0, 0xb4,
}

--- Decrypt an 8 byte block of a ByteArray in place.
-- Block byte n (1..8) is data[offset + n]; the first byte holds the shuffle flags.
-- @param data   ByteArray (0 based) containing the block
-- @param offset index of the byte BEFORE the block (the block spans offset+1 .. offset+8)
function CaDATools.Decrypt(data, offset)
    -- 1) Reverse the SwitchSheet substitution: find the original byte for every encrypted byte.
    for idx = 1, 8 do
        local val = data:get_index(offset + idx)
        for orig = 0, 255 do
            local base = SwitchSheet[orig // 4 + 1]
            if base + (orig % 4) == val then
                data:set_index(offset + idx, orig)
                break
            end
        end
    end

    -- 2) Reverse the XOR with block byte 2 and the constant 0x69 (for bytes 3..8).
    for i = 3, 8 do
        data:set_index(offset + i, data:get_index(offset + i) ~ data:get_index(offset + 2) ~ 0x69)
    end

    -- 3) Reverse the bit-level shuffles, one step per flag bit of the first block byte, from
    --    the highest bit (0x80) down to 0x01. Every step swaps nibbles between two bytes.
    local d0 = data:get_index(offset + 1)

    -- 0x80: swap the high nibble of byte 3 with the low nibble of byte 4.
    if d0 & 0x80 ~= 0 then
        local saved_4 = data:get_index(offset + 4)
        local saved_3 = data:get_index(offset + 3)
        data:set_index(offset + 4, ((saved_4 & 0xf0) | ((saved_3 & 0xf0) >> 4)) & 0xff)
        data:set_index(offset + 3, ((saved_3 & 0x0f) | ((saved_4 & 0x0f) << 4)) & 0xff)
    end

    -- 0x40: swap the low nibble of byte 3 with the high nibble of byte 4.
    if d0 & 0x40 ~= 0 then
        local saved_4 = data:get_index(offset + 4)
        local saved_3 = data:get_index(offset + 3)
        data:set_index(offset + 4, ((saved_4 & 0x0f) | ((saved_3 & 0x0f) << 4)) & 0xff)
        data:set_index(offset + 3, ((saved_3 & 0xf0) | ((saved_4 & 0xf0) >> 4)) & 0xff)
    end

    -- 0x20: swap the high nibble of byte 7 with the low nibble of byte 8.
    if d0 & 0x20 ~= 0 then
        local saved_8 = data:get_index(offset + 8)
        local saved_7 = data:get_index(offset + 7)
        data:set_index(offset + 8, ((saved_8 & 0xf0) | ((saved_7 & 0xf0) >> 4)) & 0xff)
        data:set_index(offset + 7, ((saved_7 & 0x0f) | ((saved_8 & 0x0f) << 4)) & 0xff)
    end

    -- 0x10: swap the high nibbles of bytes 6 and 8.
    if d0 & 0x10 ~= 0 then
        local saved_8 = data:get_index(offset + 8)
        local saved_6 = data:get_index(offset + 6)
        data:set_index(offset + 8, ((saved_8 & 0x0f) | (saved_6 & 0xf0)) & 0xff)
        data:set_index(offset + 6, ((saved_6 & 0x0f) | (saved_8 & 0xf0)) & 0xff)
    end

    -- 0x08: intended: swap the high nibble of byte 4 with the low nibble of byte 5.
    -- NOTE: saved_4 is read from offset + 5 (not offset + 4) like in the original code. That
    -- looks like a copy/paste typo, but correcting it would change the decoded values, so the
    -- behaviour is deliberately preserved. Verify against the app before changing it.
    if d0 & 0x08 ~= 0 then
        local saved_5 = data:get_index(offset + 5)
        local saved_4 = data:get_index(offset + 5)
        data:set_index(offset + 5, ((saved_5 & 0xf0) | ((saved_4 & 0xf0) >> 4)) & 0xff)
        data:set_index(offset + 4, ((saved_4 & 0x0f) | ((saved_5 & 0x0f) << 4)) & 0xff)
    end

    -- 0x04: swap the low nibble of byte 4 with the high nibble of byte 5 (byte 4 is not masked
    -- before the shift; the final & 0xff makes that irrelevant).
    if d0 & 0x04 ~= 0 then
        local saved_5 = data:get_index(offset + 5)
        local saved_4 = data:get_index(offset + 4)
        data:set_index(offset + 5, ((saved_5 & 0x0f) | (saved_4 << 4)) & 0xff)
        data:set_index(offset + 4, ((saved_4 & 0xf0) | ((saved_5 & 0xf0) >> 4)) & 0xff)
    end

    -- 0x02: swap the high nibble of byte 3 with the low nibble of byte 6.
    if d0 & 0x02 ~= 0 then
        local saved_6 = data:get_index(offset + 6)
        local saved_3 = data:get_index(offset + 3)
        data:set_index(offset + 6, ((saved_6 & 0xf0) | ((saved_3 & 0xf0) >> 4)) & 0xff)
        data:set_index(offset + 3, ((saved_3 & 0x0f) | ((saved_6 & 0x0f) << 4)) & 0xff)
    end

    -- 0x01: swap the low nibbles of bytes 3 and 7.
    if d0 & 0x01 ~= 0 then
        local saved_7 = data:get_index(offset + 7)
        local saved_3 = data:get_index(offset + 3)
        data:set_index(offset + 7, ((saved_7 & 0xf0) | (saved_3 & 0x0f)) & 0xff)
        data:set_index(offset + 3, ((saved_3 & 0xf0) | (saved_7 & 0x0f)) & 0xff)
    end
end

return CaDATools
