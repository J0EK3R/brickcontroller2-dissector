-- get current path
local info   = debug.getinfo(1, "S").source
local script = info:sub(2)
local bindir = script:match("(.+)[/\\]")

-- extend package.path with current path
package.path = package.path .. ";" .. bindir .. "/?.lua"

-- load modul
local CryptTools = require("CryptTools")
local CaDATools = require("CaDATools")

-- Define a new protocol for post-dissector usage.
local CaDADissector = Proto("CaDA", "Global Frame Analyzer for Bluetooth LE from CaDA")

local HeaderArray = { 0x71, 0x0f, 0x55 }
local SeedArray_CaDA = { 0x43, 0x41, 0x52 }
local CTXValue1_CaDA = 0x3f
local CTXValue2_CaDA = 0x26

function CaDADissector.dissector(buffer, pinfo, tree)

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

    -- todo: 
	local manufacturerSpecific_flags = 
        buffer(advDataOffset + 0,  1):uint() == 0x02 and -- Length: 2
        buffer(advDataOffset + 1,  1):uint() == 0x01 and -- type: Flags (0x01)
        buffer(advDataOffset + 2,  1):uint() == 0x02

    local service_flags = 
        buffer(advDataOffset + 0,  1):uint() == 0x02 and -- Length: 2
        buffer(advDataOffset + 1,  1):uint() == 0x01 and -- type: Flags (0x01)
        buffer(advDataOffset + 2,  1):uint() == 0x1a
	
	if not (manufacturerSpecific_flags or service_flags) then 
		return 0
	end
	
	local frameinfo = "unknown"
	local datagramname
	local rawData

	-- Android
	if manufacturerSpecific_flags then

        local manufacturerSpecific_Company_0xc200 = 
            buffer(advDataOffset + 3,  1):uint() == 0x1b and -- Length: 27
            buffer(advDataOffset + 4,  1):uint() == 0xff and -- type: Manufacturer Specific (0xff) 
            buffer(advDataOffset + 5,  1):uint() == 0x00 and -- Company Id 0xc200 (CaDA)
            buffer(advDataOffset + 6,  1):uint() == 0xc2

		-- CaDA
		if manufacturerSpecific_Company_0xc200 then
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
                    CaDATools.Decrypt(rawData, 7)
				else
					frameinfo = "CaDA - Android - unknown"
				end
				pinfo.cols.info = frameinfo

                if tree and rawData then
                    local tvb = ByteArray.tvb(rawData, frameinfo)
                    local subtree = tree:add(CaDADissector, tvb(), frameinfo)
                    subtree:add(tvb(), datagramname .. " - Len: " .. tvb():len())
                    subtree:add(tvb( 0, 1), "Id: 0x" .. tvb( 0, 1))
                    subtree:add(tvb( 1, 1), "Cmd: 0x" .. tvb( 1, 1))
                    subtree:add(tvb( 2, 3), "DeviceAddr: 0x" .. tvb( 2, 3))
                    subtree:add(tvb( 5, 3), "AppAddr: 0x" .. tvb( 5, 3))
                    subtree:add(tvb( 8, 2), "Random: 0x" .. tvb( 8, 2))
                    subtree:add(tvb(10, 1), "Channel 1: 0x" .. tvb(10, 1))
                    subtree:add(tvb(11, 1), "Channel 2: 0x" .. tvb(11, 1))
                    subtree:add(tvb(12, 1), "Channel 3: 0x" .. tvb(12, 1))
                end
			else
				frameinfo = "CaDA - Android - unknown"
				pinfo.cols.info = frameinfo

                if tree and rawData then
                    local tvb = ByteArray.tvb(rawData, frameinfo)
                    local subtree = tree:add(CaDADissector, tvb(), frameinfo)
                    subtree:add(tvb(), datagramname .. " - Len: " .. tvb():len())
                end
            end
            
        end

	-- iOS
	elseif service_flags then
        local cadaResponse = 
            buffer(advDataOffset + 3,  1):uint() == 0x13 and -- Length: 19
            buffer(advDataOffset + 4,  1):uint() == 0xff and -- type: Manufacturer Specific (0xff) 
            buffer(advDataOffset + 5,  1):uint() == 0xf0 and -- Company Id 0xfff0
            buffer(advDataOffset + 6,  1):uint() == 0xff and
            buffer(advDataOffset + 7,  1):uint() == 0x75 and -- CaDA identifier
            bit.band(buffer(advDataOffset + 8,  1):uint(), 0x40) > 0

		if cadaResponse then
			local rawDataOffset = 36
			local rawDataLength = 16

            resultDataLength = 8
            frameinfo = "CaDA - Android - Response"
            datagramname = "Response-Datagram"
			pinfo.cols.info = frameinfo
			
			rawData = buffer(rawDataOffset,rawDataLength):bytes()

            if tree and rawData then
                local tvb = ByteArray.tvb(rawData, frameinfo)
                local subtree = tree:add(CaDADissector, tvb(), frameinfo)
                subtree:add(tvb(), datagramname .. " - Len: " .. tvb():len())
                subtree:add(tvb( 0, 1), "Id: 0x" .. tvb( 0, 1))
                subtree:add(tvb( 1, 1), "Cmd: 0x" .. tvb( 1, 1))
                subtree:add(tvb( 2, 3), "DeviceAddr: 0x" .. tvb( 2, 3))
                subtree:add(tvb( 5, 3), "AppAddr: 0x" .. tvb( 5, 3))
            end
        end
	else
		return 0
	end
end

-- Register as a post-dissector; this will run for every frame.
register_postdissector(CaDADissector)


