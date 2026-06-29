-- get current path
local info   = debug.getinfo(1, "S").source
local script = info:sub(2)
local bindir = script:match("(.+)[/\\]")

-- extend package.path with current path
package.path = package.path .. ";" .. bindir .. "/?.lua"

-- load modul
local CryptTools = require("Crypt_Tools")

-- Define a new protocol for post-dissector usage.
local PowerBoxDissector = Proto("PowerBox", "Global Frame Analyzer for Bluetooth LE from PowerBox")

local SeedArray = { 0xC1, 0xC2, 0xC3, 0xC4, 0xC5 }
local CTXValue1 = 0x3f
local CTXValue2 = 0x25

function PowerBoxDissector.dissector(buffer, pinfo, tree)

    -- check protocol string
	if not tostring(pinfo.cols.protocol) == "LE LL" then
		return 0
	end

	local length = buffer:len()

    -- advertisingdata starts here
    local advDataOffset = 29

	local powerbox_Android_Identifier = 
        length == 57 and
        buffer(advDataOffset +  3,  1):uint() == 0x15 and -- Length: 21
        buffer(advDataOffset +  4,  1):uint() == 0xff and -- type: Manufacturer Specific (0xff) 
        buffer(advDataOffset +  5,  1):uint() == 0x00 and -- Company Id 0xff00
        buffer(advDataOffset +  6,  1):uint() == 0xff and
        buffer(advDataOffset +  7,  1):uint() == 0x6d and -- Identifier
        buffer(advDataOffset +  8,  1):uint() == 0xb6 and
        buffer(advDataOffset +  9,  1):uint() == 0x43 and
        buffer(advDataOffset + 10,  1):uint() == 0xcf and
        buffer(advDataOffset + 11,  1):uint() == 0x7e and
        buffer(advDataOffset + 12,  1):uint() == 0x8f and
        buffer(advDataOffset + 13,  1):uint() == 0x47 and
        buffer(advDataOffset + 14,  1):uint() == 0x11 and
        true                                              -- enabled

	if not (powerbox_Android_Identifier) then 
		return 0
	end

	local frameinfo = "unknown"
	local platform = "unknown"
	local manufacturer = "PowerBox"
	local datagramname = "8-Byte Payload"
	local rawData
	local rawDataOffset
	local rawDataLength
	local headerOffset
	local resultDataLength = 8
	local seedArray
	local ctxValue1
	local ctxValue2

	-- Android
	if powerbox_Android_Identifier then
		
		platform = "Android"
		rawDataOffset = advDataOffset + 7
		rawDataLength = 19
		headerOffset = 15
		seedArray = SeedArray
		ctxValue1 = CTXValue1
		ctxValue2 = CTXValue2

	else
		return 0
	end

	local data = buffer(rawDataOffset,rawDataLength)
	rawData = CryptTools.DecryptRfPayload(seedArray, 3, resultDataLength, headerOffset, ctxValue1, ctxValue2, data:bytes())

	if rawData then
		local command = rawData:get_index(0)
		local commandLength = rawData:len()
		
		datagramname = datagramname .. " - Command: " .. string.format("0x%02x", command) .. " - Length: " .. commandLength

		if command == 0xa4 then

			manufacturer = "PowerBox"
			datagramname = "Connect"
			
		elseif command == 0x40 then

			manufacturer = "PowerBox"
			datagramname = "Command" ..
				string.format(" %02x", rawData:get_index(3)) ..
				string.format(" %02x", rawData:get_index(4)) ..
				string.format(" %02x", rawData:get_index(5)) ..
				string.format(" %02x", rawData:get_index(6))
			
		else

			manufacturer = "Unknown"
			datagramname = string.format("unknown - 0x%02x", command)

		end
	
	else

		datagramname = "Decryption failed"

	end

    frameinfo = platform .. " - " .. manufacturer .. " - " .. datagramname

	if tree and rawData then
		local tvb1 = ByteArray.tvb(data:bytes(), frameinfo)
		local subtree1 = tree:add(PowerBoxDissector, tvb1(), platform .. " - " .. manufacturer .. " - Payload")
		subtree1:add(tvb1(), "Len: " .. tvb1():len())

		local tvb2 = ByteArray.tvb(rawData, frameinfo)
		local subtree2 = tree:add(PowerBoxDissector, tvb2(), platform .. " - " .. manufacturer .. " - decrypted")
		subtree2:add(tvb2(), datagramname .. "-Datagram - Len: " .. tvb2():len())
	end
	pinfo.cols.info = frameinfo

end

-- Register as a post-dissector; this will run for every frame.
register_postdissector(PowerBoxDissector)


