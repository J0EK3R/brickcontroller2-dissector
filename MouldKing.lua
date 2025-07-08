-- get current path
local info   = debug.getinfo(1, "S").source
local script = info:sub(2)
local bindir = script:match("(.+)[/\\]")

-- extend package.path with current path
package.path = package.path .. ";" .. bindir .. "/?.lua"

-- load modul
local CryptTools = require("Crypt_Tools")

-- Define a new protocol for post-dissector usage.
local MouldKingDissector = Proto("MouldKing", "Global Frame Analyzer for Bluetooth LE from MouldKing")

local HeaderArray = { 0x71, 0x0f, 0x55 }
local SeedArray_MK = { 0xC1, 0xC2, 0xC3, 0xC4, 0xC5 }
local CTXValue1_MK = 0x3f
local CTXValue2_MK = 0x25

function MouldKingDissector.dissector(buffer, pinfo, tree)

    -- check protocol string
	if not tostring(pinfo.cols.protocol) == "LE LL" then
		return 0
	end

	local length = buffer:len()

    -- check buffer length
    if not (length == 63 or length == 55) then 
		return 0
	end

    -- advertisingdata starts here
    local advDataOffset = 29

	local mouldking_Android_Identifier = 
        buffer(advDataOffset +  7,  1):uint() == 0x6d and
        buffer(advDataOffset +  8,  1):uint() == 0xb6 and
        buffer(advDataOffset +  9,  1):uint() == 0x43 and
        buffer(advDataOffset + 10,  1):uint() == 0xcf and
        buffer(advDataOffset + 11,  1):uint() == 0x7e and
        buffer(advDataOffset + 12,  1):uint() == 0x8f and
        buffer(advDataOffset + 13,  1):uint() == 0x47 and
        buffer(advDataOffset + 14,  1):uint() == 0x11

    local mouldking_iOS_Identifier = 
        buffer(advDataOffset +  5,  1):uint() == 0xf9 and
        buffer(advDataOffset +  6,  1):uint() == 0x08 and
        buffer(advDataOffset +  7,  1):uint() == 0x49 and
        buffer(advDataOffset +  8,  1):uint() == 0x22 and
        buffer(advDataOffset +  9,  1):uint() == 0x47 and
        buffer(advDataOffset + 10,  1):uint() == 0xba and
        buffer(advDataOffset + 11,  1):uint() == 0xc4 and
        buffer(advDataOffset + 12,  1):uint() == 0xbc
	
	if not (mouldking_Android_Identifier or mouldking_iOS_Identifier) then 
		return 0
	end
	
	local frameinfo = "unknown"
	local platform = "unknown"
	local manufacturer = "MouldKing"
	local datagramname
	local rawData
	local rawDataOffset
	local rawDataLength
	local headerOffset
	local resultDataLength = 0
	local length_is_8

	-- Android
	if mouldking_Android_Identifier then

		length_is_8 = 
			buffer(advDataOffset + 25,  1):uint() == 0x13 and -- fill bytes
			buffer(advDataOffset + 26,  1):uint() == 0x14
		
		platform = "Android"
		rawDataOffset = advDataOffset + 7
		rawDataLength = 25
		headerOffset = 15

	-- iOS
	elseif mouldking_iOS_Identifier then

		length_is_8 = 
			buffer(advDataOffset + 23,  1):uint() == 0x12 and -- fill bytes
			buffer(advDataOffset + 24,  1):uint() == 0x13

		platform = "iOS"
		rawDataOffset = advDataOffset + 5
		rawDataLength = 26
		headerOffset = 13

	end

	if length_is_8 then
		resultDataLength = 8
		datagramname = "Connect"
	else
		resultDataLength = 10
		datagramname = "Control"
	end
	
	frameinfo = platform .. " - " .. manufacturer .. " - " .. datagramname

	local data = buffer(rawDataOffset,rawDataLength)
	rawData = CryptTools.DecryptRfPayload(SeedArray_MK, 3, resultDataLength, headerOffset, CTXValue1_MK, CTXValue2_MK, data:bytes())

	if tree and rawData then
		local tvb1 = ByteArray.tvb(data:bytes(), frameinfo)
		local subtree1 = tree:add(MouldKingDissector, tvb1(), platform .. " - " .. manufacturer .. " - Payload")
		subtree1:add(tvb1(), "Len: " .. tvb1():len())

		local tvb2 = ByteArray.tvb(rawData, frameinfo)
		local subtree2 = tree:add(MouldKingDissector, tvb2(), platform .. " - " .. manufacturer .. " - decrypted")
		subtree2:add(tvb2(), datagramname .. "-Datagram - Len: " .. tvb2():len())
	end
	pinfo.cols.info = frameinfo

end

-- Register as a post-dissector; this will run for every frame.
register_postdissector(MouldKingDissector)


