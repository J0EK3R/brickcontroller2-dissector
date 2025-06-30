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
            currentResult = currentResult + (encoded_bit << bitIndex)
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

-- Define a new protocol for post-dissector usage.
local myproto = Proto("myproto", "My Global Frame Analyzer")

local HeaderArray = { 0x71, 0x0f, 0x55 }
local SeedArray_MK = { 0xC1, 0xC2, 0xC3, 0xC4, 0xC5 }
local CTXValue1_MK = 0x3f
local CTXValue2_MK = 0x25
local SeedArray_CaDA = { 0x43, 0x41, 0x52 }
local CTXValue1_CaDA = 0x3f
local CTXValue2_CaDA = 0x26

function myproto.dissector(buffer, pinfo, tree)

	if not tostring(pinfo.cols.protocol) == "LE LL" then
		return 0
	end

	length = buffer:len()

	if not (length == 63) then 
		return 0
	end

	local advertisingdata = buffer(29,31):bytes()

	local manufacturerSpecific_flags = advertisingdata:get_index(0) == 0x02 and advertisingdata:get_index(1) == 0x01 and advertisingdata:get_index(2) == 0x02
	local service_flags = advertisingdata:get_index(0) == 0x02 and advertisingdata:get_index(1) == 0x01 and advertisingdata:get_index(2) == 0x1a
	
	if not (manufacturerSpecific_flags or service_flags) then 
		return 0
	end
	
	local frameinfo = "unknown"
	local datagramname
	local rawData

	-- Android
	if manufacturerSpecific_flags then
		local manufacturerSpecific_Company_0xfff0 = advertisingdata:get_index(3) == 0x1b and advertisingdata:get_index(4) == 0xff and advertisingdata:get_index(5) == 0xf0 and advertisingdata:get_index(6) == 0xff
		local manufacturerSpecific_Company_0xc200 = advertisingdata:get_index(3) == 0x1b and advertisingdata:get_index(4) == 0xff and advertisingdata:get_index(5) == 0x00 and advertisingdata:get_index(6) == 0xc2

		-- MouldKing
		if manufacturerSpecific_Company_0xfff0 then
			local manufacturerSpecific_Connect = advertisingdata:get_index(25) == 0x13 and advertisingdata:get_index(26) == 0x14
			
			local rawDataOffset = 36
			local rawDataLength = 25
			local headerOffset = 15
			local resultDataLength = 0

			if manufacturerSpecific_Connect then
				resultDataLength = 8
				frameinfo = "MK - Android - Connect"
				datagramname = "Connect-Datagram"
			else
				resultDataLength = 10
				frameinfo = "MK - Android - Control"
				datagramname = "Control-Datagram"
			end
			
			local data = buffer(rawDataOffset,rawDataLength)
			rawData = CryptTools.DecryptRfPayload(SeedArray_MK, 3, resultDataLength, headerOffset, CTXValue1_MK, CTXValue2_MK, data:bytes())

		-- CaDA
		elseif manufacturerSpecific_Company_0xc200 then
			local rawDataOffset = 36
			local rawDataLength = 24
			local headerOffset = 15
			local resultDataLength = 0

			resultDataLength = 16
			datagramname = "CaDA-Datagram"
			
			local data = buffer(rawDataOffset,rawDataLength)
			rawData = CryptTools.DecryptRfPayload(SeedArray_CaDA, 3, resultDataLength, headerOffset, CTXValue1_CaDA, CTXValue2_CaDA, data:bytes())
			
			if rawData:get_index(0) == 0x75 then
				local command = rawData:get_index(1)
				
				if command == 0x10 then
					frameinfo = "CaDA - Android - Connect"
				elseif command == 0x13 then
					frameinfo = "CaDA - Android - Control"
				else
					frameinfo = "CaDA - Android - unknown"
				end
			else
				frameinfo = "CaDA - Android - unknown"
			end
		end

	-- iOS
	elseif service_flags then
		local service_Data = advertisingdata:get_index(3) == 0x1b and advertisingdata:get_index(4) == 0x03
		local service_Connect = advertisingdata:get_index(23) == 0x12 and advertisingdata:get_index(24) == 0x13

		if service_Data then
			local rawDataOffset = 34
			local rawDataLength = 27
			local headerOffset = 13
			local resultDataLength = 0

			if service_Connect then
				resultDataLength = 8
				frameinfo = "MK - iOS - Connect"
				datagramname = "Connect-Datagram"
			else
				resultDataLength = 10
				frameinfo = "MK - iOS - Control"
				datagramname = "Control-Datagram"
			end
			
			local data = buffer(rawDataOffset,rawDataLength)
			rawData = CryptTools.DecryptRfPayload(SeedArray_MK, 3, resultDataLength, headerOffset, CTXValue1_MK, CTXValue2_MK, data:bytes())
		end
	else
		return 0
	end

	pinfo.cols.info = frameinfo

	if tree and rawData then
		local tvb = ByteArray.tvb(rawData, "My Tvb")
		local subtree = tree:add(myproto, tvb(), frameinfo)
		subtree:add(tvb(), datagramname .. " - Len: " .. tvb():len())
	end
end

-- Register as a post-dissector; this will run for every frame.
register_postdissector(myproto)


