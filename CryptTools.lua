-- CryptTools.lua
-- A Lua conversion of the C# CryptTools class.
-- (Note: This code assumes Lua 5.3+ with built-in bit operators.)

local CryptTools = {}

-- Helper: block-copy len bytes from src at srcOffset to dest at destOffset.
local function block_copy(src, srcOffset, dest, destOffset, length)
    for i = 0, length - 1 do
        dest[destOffset + i] = src[srcOffset + i]
    end
end

-- Helper: read a UInt16 (big-endian) from buffer at offset.
local function get_uint16(buffer, offset)
    return (buffer[offset] << 8) | buffer[offset + 1]
end

-- Helper: write a UInt16 (big-endian) to buffer at offset.
local function set_uint16(buffer, offset, value)
    buffer[offset]     = (value >> 8) & 0xFF
    buffer[offset + 1] = value & 0xFF
end


----------------------------------------
-- Invert8:
-- Inverts the bits in an 8-bit value.
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
-- Invert16:
-- Inverts the bits in a 16-bit value.
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
-- CheckCRC16:
-- Calculates CRC16 over two byte arrays.
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
-- WhiteningInit:
-- Initializes the ctx array (of length 7) with the given value.
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
-- WhiteningOutput:
-- Updates and returns the output bit from the ctx array.
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
-- WhiteningEncode:
-- Encodes (or decodes, since it is XOR based) the data bytes using a whitening ctx.
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
-- GetRfPayload:
-- Encrypts the header and data using seed and ctx values. The output is placed into rfPayload.
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
-- DecryptRfPayload:
-- Decrypts an rfPayload using the provided seed, header/data lengths, header offset, and ctx values.
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
    -- block_copy(rfPayload, 0, resultBuffer, headerOffset, resultArrayLength)
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

    -- Extract header and inverted seed.
    local header = {}
    for i = 0, headerLength - 1 do
        header[i] = CryptTools.Invert8(resultBuffer[headerOffset + i])
    end

    local seedReversed = {}
    for i = 0, seedLength - 1 do
        seedReversed[i] = CryptTools.Invert8(resultBuffer[headerOffset + headerLength + i])
    end

    -- Reverse the seed to obtain its original order.
    local seedOriginal = {}
    for i = 0, seedLength - 1 do
        seedOriginal[i] = seedReversed[seedLength - 1 - i]
    end

    -- Extract data.
    local dataOut = ByteArray.new()
	dataOut:set_size(dataLength)
	
    for i = 0, dataLength - 1 do
        dataOut:set_index(i, resultBuffer[dataOffset + i])
    end

    -- local expectedCrc = get_uint16(resultBuffer, checksumOffset)
    -- local actualCrc = CryptTools.CheckCRC16(seedOriginal, dataOut)

    -- if expectedCrc ~= actualCrc then
        -- error("CRC check failed. Data may be corrupted or parameters are incorrect.")
    -- end

    return dataOut
end

return CryptTools