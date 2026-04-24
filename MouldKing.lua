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

    -- advertisingdata starts here
    local advDataOffset = 29

	local mouldking_Android_Identifier = 
        length == 63 and
        buffer(advDataOffset +  3,  1):uint() == 0x1b and -- Length: 27
        buffer(advDataOffset +  4,  1):uint() == 0xff and -- type: Manufacturer Specific (0xff) 
        buffer(advDataOffset +  5,  1):uint() == 0xf0 and -- Company Id 0xfff0
        buffer(advDataOffset +  6,  1):uint() == 0xff and
        buffer(advDataOffset +  7,  1):uint() == 0x6d and -- MouldKing identifier
        buffer(advDataOffset +  8,  1):uint() == 0xb6 and
        buffer(advDataOffset +  9,  1):uint() == 0x43 and
        buffer(advDataOffset + 10,  1):uint() == 0xcf and
        buffer(advDataOffset + 11,  1):uint() == 0x7e and
        buffer(advDataOffset + 12,  1):uint() == 0x8f and
        buffer(advDataOffset + 13,  1):uint() == 0x47 and
        buffer(advDataOffset + 14,  1):uint() == 0x11 and
        true                                              -- enabled

    local mouldking_iOS_Identifier = 
        length == 55 and
        buffer(advDataOffset +  5,  1):uint() == 0xf9 and
        buffer(advDataOffset +  6,  1):uint() == 0x08 and
        buffer(advDataOffset +  7,  1):uint() == 0x49 and
        buffer(advDataOffset +  8,  1):uint() == 0x22 and
        buffer(advDataOffset +  9,  1):uint() == 0x47 and
        buffer(advDataOffset + 10,  1):uint() == 0xba and
        buffer(advDataOffset + 11,  1):uint() == 0xc4 and
        buffer(advDataOffset + 12,  1):uint() == 0xbc and
        true                                              -- enabled

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

	else
		return 0
	end

	if length_is_8 then
		resultDataLength = 8
		datagramname = "8-Byte Payload"
	else
		resultDataLength = 10
		datagramname = "10-Byte Payload"
	end
	
	local data = buffer(rawDataOffset,rawDataLength)
	rawData = CryptTools.DecryptRfPayload(SeedArray_MK, 3, resultDataLength, headerOffset, CTXValue1_MK, CTXValue2_MK, data:bytes())

	if rawData then
		local command = rawData:get_index(0)
		
		-- MK2.0
		-- MK3.0
		-- MK4.0D
		-- MK8.0
		if command == 0xaa then
			-- MK2.0   aa 7b a7 00 00 00 00 55
			-- MK3.0   aa 7b a7 00 00 00 00 55
			-- MK4.0D  aa 7b a7 00 00 00 00 55
			-- MK8.0   aa 7b a7 00 00 00 00 55

			manufacturer = "MouldKing"
			datagramname = "MK2.0/MK3.0/MK4.0D/MK8.0 Connect"

		elseif command == 0x66 then
			-- MK2.0   66 7b a7 80 80 80 80 99
			-- MK3.0   66 7b a7 80 80 80 80 99
			-- MK4.0D  66 7b a7 80 80 80 80 99
			-- MK8.0   66 7b a7 80 80 80 80 99

			manufacturer = "MouldKing"
			datagramname = "MK2.0/MK3.0/MK4.0D/MK8.0 Command"

		elseif command == 0x77 then
			-- MK4.0D  77 7b a7 00 00 00 00 88

			manufacturer = "MouldKing"
			datagramname = "MK4.0D Command"
		
		-- MK3.8
		elseif command == 0xB1 then
			-- MK3.8   b1 7b a7 80 80 80 4f c1

			manufacturer = "MouldKing"
			datagramname = "MK3.8 Connect"

		elseif command == 0x81 then
			-- MK3.8   81 7b 00 99 99 99 99 99 99 c2

			manufacturer = "MouldKing"
			datagramname = "MK3.8 Command"
		
		-- MK4.0
		-- MK5.0 
		-- 4P Blade 4.0
		elseif command == 0xad then
			-- MK4.0   ad 7b a7 80 80 80 4f 52
			-- MK5.0   ad 7b a7 80 80 80 4f 52

			manufacturer = "MouldKing"
			datagramname = "MK4.0/MK5.0 Connect"
			
		elseif command == 0x7d then
			-- MK4.0   7d 7b a7 88 88 88 88 88 88 82
			-- MK5.0   7d 7b a7 00 00 80 80 80 80 82

			manufacturer = "MouldKing"
			datagramname = "MK4.0/MK5.0 Command"
		
		-- MK6.0
		-- Mecanum
		-- 4P Blade 6.0
		elseif command == 0x6d then
			-- MK6.0   6d 7b a7 80 80 80 80 92
			-- Mecanum 6d 7b a7 80 80 80 80 92

			manufacturer = "MouldKing"
			datagramname = "MK6.0 Connect"

		elseif command == 0x61 then
			-- MK6.0[1]   61 7b a7 80 80 80 80 80 80 9e
			-- Mecanum    61 7b a7 80 80 80 80 80 80 9e
			
			manufacturer = "MouldKing"
			datagramname = "MK6.0[1] Command"
			
		elseif command == 0x62 then
			-- MK6.0[2]   62 7b a7 80 80 01 80 80 80 9d

			manufacturer = "MouldKing"
			datagramname = "MK6.0[2] Command"
			
		elseif command == 0x63 then
			-- MK6.0[3]   63 7b a7 80 80 80 80 80 80 9c

			manufacturer = "MouldKing"
			datagramname = "MK6.0[3] Command"

		elseif command == 0xa4 then
			local _3rd = rawData:get_index(3)

			if _3rd == 0x00 then
				-- JIE-STAR 8CH   a4 1d 74 00 00 00 00 5b

				manufacturer = "JIE-STAR"
				datagramname = "JIE-STAR 8CH Connect"

			elseif _3rd == 0x80 then
				-- JIE-STAR 4CH   a4 1d 74 80 80 80 80 5b

				manufacturer = "JIE-STAR"
				datagramname = "JIE-STAR 4CH Connect"
				
			else

				manufacturer = "JIE-STAR"
				datagramname = string.format("unknown - 0x%02x", command)
				
			end

		elseif command == 0x40 then
			-- JIE-STAR 4CH   40 1d 74 80 80 80 80 bf

			manufacturer = "JIE-STAR"
			datagramname = "JIE-STAR 4CH[1] Command"
			
		elseif command == 0x41 then
			-- JIE-STAR 8CH   41 1d 74 00 00 00 00 bf

			manufacturer = "JIE-STAR"
			datagramname = "JIE-STAR 8CH[1] Command"
			
		elseif command == 0x42 then
			-- JIE-STAR 8CH   42 1d 74 00 00 00 00 be

			manufacturer = "JIE-STAR"
			datagramname = "JIE-STAR 8CH[2] Command"
			
		elseif command == 0x43 then
			-- JIE-STAR 8CH   43 1d 74 00 00 00 00 bd

			manufacturer = "JIE-STAR"
			datagramname = "JIE-STAR 8CH[3] Command"
			
		else

			manufacturer = "Unknown"
			datagramname = string.format("unknown - 0x%02x", command)

		end
	end

    frameinfo = platform .. " - " .. manufacturer .. " - " .. datagramname

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


