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
local BrickController = Proto("BrickController", "Global Frame Analyzer for Bluetooth LE Broadcast")

local HeaderArray = { 0x71, 0x0f, 0x55 }
local SeedArray_MK = { 0xC1, 0xC2, 0xC3, 0xC4, 0xC5 }
local CTXValue1_MK = 0x3f
local CTXValue2_MK = 0x25
local SeedArray_CaDA = { 0x43, 0x41, 0x52 }
local CTXValue1_CaDA = 0x3f
local CTXValue2_CaDA = 0x26

function BrickController.dissector(buffer, pinfo, tree)

    -- check protocol string
	if not tostring(pinfo.cols.protocol) == "LE LL" then
		return 0
	end

	local length = buffer:len()

    -- check buffer length
    if not (length == 63) then 
		return 0
	end

    -- get advertisingdata
	local advertisingdata = buffer(29,31):bytes()

    -- todo: 
	local manufacturerSpecific_flags = 
        advertisingdata:get_index(0) == 0x02 and -- Length: 2
        advertisingdata:get_index(1) == 0x01 and -- type: Flags (0x01)
        advertisingdata:get_index(2) == 0x02

    local service_flags = 
        advertisingdata:get_index(0) == 0x02 and -- Length: 2
        advertisingdata:get_index(1) == 0x01 and -- type: Flags (0x01)
        advertisingdata:get_index(2) == 0x1a
	
	if not (manufacturerSpecific_flags or service_flags) then 
		return 0
	end
	
	local frameinfo = "unknown"
	local datagramname
	local rawData

	-- Android
	if manufacturerSpecific_flags then
		local manufacturerSpecific_Company_0xfff0 = 
            advertisingdata:get_index(3) == 0x1b and -- Length: 27
            advertisingdata:get_index(4) == 0xff and -- type: Manufacturer Specific (0xff) 
            advertisingdata:get_index(5) == 0xf0 and -- Company Id 0xfff0
            advertisingdata:get_index(6) == 0xff

        local manufacturerSpecific_Company_0xc200 = 
            advertisingdata:get_index(3) == 0x1b and -- Length: 27
            advertisingdata:get_index(4) == 0xff and -- type: Manufacturer Specific (0xff) 
            advertisingdata:get_index(5) == 0x00 and -- Company Id 0xc200 (CaDA)
            advertisingdata:get_index(6) == 0xc2

		-- MouldKing
		if manufacturerSpecific_Company_0xfff0 then
			local manufacturerSpecific_Connect = 
                advertisingdata:get_index(25) == 0x13 and -- fill bytes
                advertisingdata:get_index(26) == 0x14
			
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

            if tree and rawData then
                local tvb = ByteArray.tvb(rawData, frameinfo)
                local subtree = tree:add(BrickController, tvb(), frameinfo)
                subtree:add(tvb(), datagramname .. " - Len: " .. tvb():len())
            end

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
                    CaDATools.Decrypt(rawData, 7)
				else
					frameinfo = "CaDA - Android - unknown"
				end
			else
				frameinfo = "CaDA - Android - unknown"
			end

            if tree and rawData then
                local tvb = ByteArray.tvb(rawData, frameinfo)
                local subtree = tree:add(BrickController, tvb(), frameinfo)
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
            
        end

	-- iOS
	elseif service_flags then
		local service_Data = 
            advertisingdata:get_index(3) == 0x1b and -- Length: 27
            advertisingdata:get_index(4) == 0x03     -- type: 16-bit Service Class UUIDs (0x03)

		local service_Connect = 
            advertisingdata:get_index(23) == 0x12 and -- fill bytes
            advertisingdata:get_index(24) == 0x13

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

            if tree and rawData then
                local tvb = ByteArray.tvb(rawData, frameinfo)
                local subtree = tree:add(BrickController, tvb(), frameinfo)
                subtree:add(tvb(), datagramname .. " - Len: " .. tvb():len())
            end
        end
	else
		return 0
	end

	pinfo.cols.info = frameinfo
end

-- Register as a post-dissector; this will run for every frame.
register_postdissector(BrickController)


