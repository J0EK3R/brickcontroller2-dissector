-- Crypt_Tools.lua
--
-- Encryption / decryption of the RF payloads of the MouldKing, JIE-STAR, PowerBox and CaDA
-- "PC" advertising datagrams. A Lua conversion of the C# CryptTools class of the app.
--
-- Payload layout (before whitening), all offsets relative to the start of the RF payload:
--   header (3 bytes) | seed (5 or 3 bytes, stored reversed) | data | CRC16 (2 bytes, big endian)
-- Header and seed are bit-inverted, then two whitening passes (LFSR, XOR based) are applied:
-- the first over seed+data+CRC with ctxValue1, the second over the complete buffer with
-- ctxValue2. Decrypting is the same sequence in reverse order.
--
-- All tables used here are 0 based (like the C# arrays); Wireshark ByteArrays are 0 based too.
-- Needs Lua 5.3 or newer: native bit operators (& | ~ << >>) are used.

local CryptTools = {}

--- Block-copy `length` bytes from src at srcOffset to dest at destOffset (0 based tables).
local function block_copy(src, srcOffset, dest, destOffset, length)
    for i = 0, length - 1 do
        dest[destOffset + i] = src[srcOffset + i]
    end
end

--- Write a UInt16 (big-endian) to buffer at offset.
local function set_uint16(buffer, offset, value)
    buffer[offset]     = (value >> 8) & 0xFF
    buffer[offset + 1] = value & 0xFF
end


----------------------------------------
--- Invert8: reverse the bit order of an 8-bit value (0x01 -> 0x80).
-- @param value integer 0..255
-- @return integer 0..255
function CryptTools.Invert8(value)
    local result = 0
    for index = 0, 7 do
        if (value & (1 << index)) ~= 0 then
            result = result | (1 << (7 - index))
        end
    end
    return result & 0xFF
end

----------------------------------------
--- Invert16: reverse the bit order of a 16-bit value (0x0001 -> 0x8000).
-- @param value integer 0..65535
-- @return integer 0..65535
function CryptTools.Invert16(value)
    local result = 0
    for index = 0, 15 do
        if (value & (1 << index)) ~= 0 then
            result = result | (1 << (15 - index))
        end
    end
    return result & 0xFFFF
end

----------------------------------------
--- CheckCRC16: calculate the CRC16 (polynomial 0x1021, start value 0xFFFF) over two arrays.
-- array1 (the seed) is processed in reverse order as it is, array2 (the data) in forward
-- order with every byte bit-inverted. The result is bit-inverted and XORed with 0xFFFF.
-- Only used when encrypting (GetRfPayload); decrypting does not verify the CRC.
-- @param array1 table of bytes (seed)
-- @param array2 0 based table or ByteArray of bytes (data)
-- @return integer 0..65535
function CryptTools.CheckCRC16(array1, array2)
    local result = 0xFFFF

    -- Process the first array in reverse order.
    local array1Length = #array1
    for index = 0, array1Length - 1 do
        -- Note: since our tables are 0-indexed, the last element is at index array1Length-1.
        result = result ~ (array1[array1Length - 1 - index] << 8)
        for local_24 = 0, 7 do
            if (result & 0x8000) == 0 then
                result = (result << 1) & 0xFFFF
            else
                result = ((result << 1) ~ 0x1021) & 0xFFFF
            end
        end
    end

    local array2Length = #array2
    for index = 0, array2Length - 1 do
        local cVar1 = CryptTools.Invert8(array2[index])
        result = result ~ (cVar1 << 8)
        for local_2c = 0, 7 do
            if (result & 0x8000) == 0 then
                result = (result << 1) & 0xFFFF
            else
                result = ((result << 1) ~ 0x1021) & 0xFFFF
            end
        end
    end

    local result_inverse = CryptTools.Invert16(result)
    return (result_inverse ~ 0xFFFF) & 0xFFFF
end

----------------------------------------
--- WhiteningInit: initialize the 7 bit LFSR state `ctx` (0 based table) from a 6 bit value.
-- ctx[0] is always 1, ctx[1..6] are the bits 5..0 of `val`.
function CryptTools.WhiteningInit(val, ctx)
    ctx[0] = 1
    ctx[1] = (val >> 5) & 1
    ctx[2] = (val >> 4) & 1
    ctx[3] = (val >> 3) & 1
    ctx[4] = (val >> 2) & 1
    ctx[5] = (val >> 1) & 1
    ctx[6] = val & 1
end

----------------------------------------
--- WhiteningOutput: shift the LFSR once and return the output bit (0 or 1).
function CryptTools.WhiteningOutput(ctx)
    local value_3 = ctx[3]
    local value_6 = ctx[6]
    ctx[3] = ctx[2]
    ctx[2] = ctx[1]
    ctx[1] = ctx[0]
    ctx[0] = ctx[6]
    ctx[6] = ctx[5]
    ctx[5] = ctx[4]
    ctx[4] = value_3 ~ value_6
    return ctx[0]
end

----------------------------------------
--- WhiteningEncode: XOR `len` bytes of `data` (0 based table, starting at dataStartIndex) in
-- place with the LFSR stream (least significant bit first). The operation is its own inverse,
-- so it encodes and decodes.
function CryptTools.WhiteningEncode(data, dataStartIndex, len, ctx)
    for index = 0, len - 1 do
        local currentByte = data[dataStartIndex + index]
        local currentResult = 0
        for bitIndex = 0, 7 do
            local uVar2 = CryptTools.WhiteningOutput(ctx)
            local bit = (currentByte >> bitIndex) & 1
            local encoded_bit = uVar2 ~ bit
            currentResult = currentResult | (encoded_bit << bitIndex)
        end
        data[dataStartIndex + index] = currentResult & 0xFF
    end
end

----------------------------------------
--- GetRfPayload: encrypt header and data using seed and ctx values.
-- @param seed         0 based table of seed bytes
-- @param header       0 based table of header bytes
-- @param data         0 based table or ByteArray of the plain data
-- @param headerOffset number of leading zero bytes in the work buffer (the header position
--                     in the whitening sequence; differs per platform)
-- @param ctxValue1    whitening value of the first pass
-- @param ctxValue2    whitening value of the second pass
-- @param rfPayload    0 based output table; must be large enough
-- @return number of bytes written to rfPayload, 0 if it is too small
function CryptTools.GetRfPayload(seed, header, data, headerOffset, ctxValue1, ctxValue2, rfPayload)
    local checksumLength = 2
    local seedLength = #seed
    local headerLength = #header
    local dataLength = #data
    local resultArrayLength = headerLength + seedLength + dataLength + checksumLength

    if resultArrayLength > #rfPayload then
        return 0
    end

    local seedOffset = headerOffset + headerLength
    local dataOffset = seedOffset + seedLength
    local checksumOffset = dataOffset + dataLength
    local resultBufferLength = checksumOffset + checksumLength

    local resultBuffer = {}
    for i = 0, resultBufferLength - 1 do
        resultBuffer[i] = 0
    end

    -- Copy header into resultBuffer.
    block_copy(header, 0, resultBuffer, headerOffset, headerLength)

    -- Reverse-copy seed into resultBuffer.
    for index = 0, seedLength - 1 do
        resultBuffer[seedOffset + index] = seed[seedLength - 1 - index]
    end

    -- Invert the bytes for header + seed.
    for index = 0, headerLength + seedLength - 1 do
        resultBuffer[headerOffset + index] = CryptTools.Invert8(resultBuffer[headerOffset + index])
    end

    -- Copy data into resultBuffer.
    block_copy(data, 0, resultBuffer, dataOffset, dataLength)

    local checksum = CryptTools.CheckCRC16(seed, data)
    set_uint16(resultBuffer, checksumOffset, checksum)

    -- Whitening with first context value.
    local ctxArray1 = {0,0,0,0,0,0,0}
    CryptTools.WhiteningInit(ctxValue1, ctxArray1)
    CryptTools.WhiteningEncode(resultBuffer, seedOffset, seedLength + dataLength + checksumLength, ctxArray1)

    -- Whitening with second context value.
    local ctxArray2 = {0,0,0,0,0,0,0}
    CryptTools.WhiteningInit(ctxValue2, ctxArray2)
    CryptTools.WhiteningEncode(resultBuffer, 0, resultBufferLength, ctxArray2)

    -- Copy the final encrypted payload from resultBuffer into rfPayload.
    block_copy(resultBuffer, headerOffset, rfPayload, 0, resultArrayLength)

    return resultArrayLength
end

----------------------------------------
--- DecryptRfPayload: decrypt an RF payload (inverse of GetRfPayload).
-- The CRC is intentionally NOT verified: the dissectors should still show what a
-- frame with a wrong CRC or wrong parameters would decode to.
-- @param seed         0 based table of seed bytes (only its length is used here)
-- @param headerLength number of header bytes
-- @param dataLength   number of data bytes
-- @param headerOffset see GetRfPayload
-- @param ctxValue1    whitening value of the first pass
-- @param ctxValue2    whitening value of the second pass
-- @param rfPayload    ByteArray holding the encrypted payload
-- @return ByteArray with the `dataLength` decrypted data bytes
function CryptTools.DecryptRfPayload(seed, headerLength, dataLength, headerOffset, ctxValue1, ctxValue2, rfPayload)
    local checksumLength = 2
    local seedLength = #seed
    local resultArrayLength = headerLength + seedLength + dataLength + checksumLength

    local seedOffset = headerOffset + headerLength
    local dataOffset = seedOffset + seedLength
    local checksumOffset = dataOffset + dataLength
    local resultBufferLength = checksumOffset + checksumLength

    local resultBuffer = {}
    for i = 0, resultBufferLength - 1 do
        resultBuffer[i] = 0
    end
    -- Copy the payload to its position in the work buffer (rfPayload is a ByteArray).
    for i = 0, resultArrayLength - 1 do
        resultBuffer[headerOffset + i] = rfPayload:get_index(i)
    end

    -- Reverse the second whitening.
    local ctxArray2 = {0,0,0,0,0,0,0}
    CryptTools.WhiteningInit(ctxValue2, ctxArray2)
    CryptTools.WhiteningEncode(resultBuffer, 0, resultBufferLength, ctxArray2)

    -- Reverse the first whitening.
    local ctxArray1 = {0,0,0,0,0,0,0}
    CryptTools.WhiteningInit(ctxValue1, ctxArray1)
    CryptTools.WhiteningEncode(resultBuffer, seedOffset, seedLength + dataLength + checksumLength, ctxArray1)

    -- Extract the data bytes (header and seed are not needed by the callers).
    local dataOut = ByteArray.new()
    dataOut:set_size(dataLength)

    for i = 0, dataLength - 1 do
        dataOut:set_index(i, resultBuffer[dataOffset + i])
    end

    -- The CRC at checksumOffset is deliberately not checked (see the function comment).

    return dataOut
end

return CryptTools
