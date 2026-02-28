-- get current path
local info   = debug.getinfo(1, "S").source
local script = info:sub(2)
local bindir = script:match("(.+)[/\\]")

-- extend package.path with current path
package.path = package.path .. ";" .. bindir .. "/?.lua"

-- load modul
local CryptTools = require("Crypt_Tools")
local CaDATools = require("CaDA_Tools")

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

    -- advertisingdata starts here
    local advDataOffset = 29

    local cada_Device_Response = 
        length == 55 and
        buffer(advDataOffset +  3,  1):uint() == 0x13 and -- Length: 19
        buffer(advDataOffset +  4,  1):uint() == 0xff and -- type: Manufacturer Specific (0xff) 
        buffer(advDataOffset +  5,  1):uint() == 0xf0 and -- Company Id 0xfff0
        buffer(advDataOffset +  6,  1):uint() == 0xff and
        buffer(advDataOffset +  7,  1):uint() == 0x75 and -- CaDA identifier
        bit.band(buffer(advDataOffset + 8,  1):uint(), 0x40) > 0 and -- 
        -- buffer(advDataOffset +  9,  1):uint() == 0x31 and -- DeviceID: 0x31f5e5
        -- buffer(advDataOffset + 10,  1):uint() == 0xf5 and -- 
        -- buffer(advDataOffset + 11,  1):uint() == 0xe5 and -- 
        -- buffer(advDataOffset + 12,  1):uint() == 0x79 and --AppAddr: 0x7929cb
        -- buffer(advDataOffset + 13,  1):uint() == 0x29 and -- 
        -- buffer(advDataOffset + 14,  1):uint() == 0xcb and -- 
        -- buffer(advDataOffset + 15,  1):uint() == 0x00 and -- 
        -- buffer(advDataOffset + 16,  1):uint() == 0x00 and --
        -- buffer(advDataOffset + 17,  1):uint() == 0x00 and -- 
        -- buffer(advDataOffset + 18,  1):uint() == 0x00 and -- 
        -- buffer(advDataOffset + 19,  1):uint() == 0x00 and -- 
        -- buffer(advDataOffset + 20,  1):uint() == 0x00 and --
        -- buffer(advDataOffset + 21,  1):uint() == 0x00 and -- 
        -- buffer(advDataOffset + 22,  1):uint() == 0x00 and -- 
        true                                              -- enabled

    local cada_Android_Identifier = 
        length == 63 and
        buffer(advDataOffset +  3,  1):uint() == 0x1b and -- Length: 27
        buffer(advDataOffset +  4,  1):uint() == 0xff and -- type: Manufacturer Specific (0xff) 
        buffer(advDataOffset +  5,  1):uint() == 0x00 and -- Company Id 0xc200
        buffer(advDataOffset +  6,  1):uint() == 0xc2 and -- 
        buffer(advDataOffset +  7,  1):uint() == 0xee and -- CaDA identifier
        buffer(advDataOffset +  8,  1):uint() == 0x1b and --
        buffer(advDataOffset +  9,  1):uint() == 0xc8 and --
        buffer(advDataOffset + 10,  1):uint() == 0xaf and --
        buffer(advDataOffset + 11,  1):uint() == 0x9f and --
        buffer(advDataOffset + 12,  1):uint() == 0x3c and --
        true                                              -- enabled

    local cada_iOS_Identifier =
        length == 63 and
        buffer(advDataOffset +  3,  1):uint() == 0x1b and -- Length: 27
        buffer(advDataOffset +  4,  1):uint() == 0x03 and -- type: Complete List of 16-bit Service Class UUIDs (0x03)
        buffer(advDataOffset +  5,  1):uint() == 0xc0 and -- Company Id 0xc03d
        buffer(advDataOffset +  6,  1):uint() == 0x3d and --
        buffer(advDataOffset +  7,  1):uint() == 0xca and --
        buffer(advDataOffset +  8,  1):uint() == 0x66 and --
        buffer(advDataOffset +  9,  1):uint() == 0x6d and --
        buffer(advDataOffset + 10,  1):uint() == 0x32 and --
        -- buffer(advDataOffset + 11,  1):uint() == 0xb2 and --
        -- buffer(advDataOffset + 12,  1):uint() == 0x9e and --
        -- buffer(advDataOffset + 13,  1):uint() == 0xe3 and --
        -- buffer(advDataOffset + 14,  1):uint() == 0xa2 and --
        -- buffer(advDataOffset + 15,  1):uint() == 0x44 and --
        -- buffer(advDataOffset + 16,  1):uint() == 0x2a and --
        -- buffer(advDataOffset + 17,  1):uint() == 0xd8 and --
        -- buffer(advDataOffset + 18,  1):uint() == 0xce and --
        -- buffer(advDataOffset + 19,  1):uint() == 0x44 and --
        -- buffer(advDataOffset + 20,  1):uint() == 0x81 and --
        -- buffer(advDataOffset + 21,  1):uint() == 0x10 and --
        -- buffer(advDataOffset + 22,  1):uint() == 0x30 and --
        -- buffer(advDataOffset + 23,  1):uint() == 0x81 and --
        -- buffer(advDataOffset + 24,  1):uint() == 0x5f and --
        -- buffer(advDataOffset + 25,  1):uint() == 0xbe and --
        -- buffer(advDataOffset + 26,  1):uint() == 0x31 and --
        -- buffer(advDataOffset + 28,  1):uint() == 0x1b and --
        -- buffer(advDataOffset + 29,  1):uint() == 0x8e and --
        -- buffer(advDataOffset + 30,  1):uint() == 0x18 and --
        -- buffer(advDataOffset + 31,  1):uint() == 0x19 and --
        true                                              -- enabled

    if not (cada_Device_Response or cada_Android_Identifier or cada_iOS_Identifier) then 
		return 0
	end

    local manufacturer = "CaDA"

    if cada_Device_Response then

        local rawDataOffset = advDataOffset + 7
        local rawDataLength = 16
        local platform = "Device"

        resultDataLength = 8
        datagramname = "Response"

        frameinfo = platform .. " - " .. manufacturer .." - " .. datagramname
        pinfo.cols.info = frameinfo
     
        rawData = buffer(rawDataOffset,rawDataLength):bytes()

        if tree and rawData then
            local tvb2 = ByteArray.tvb(rawData, frameinfo)
            local subtree2 = tree:add(CaDADissector, tvb2(), frameinfo)
            subtree2:add(tvb2(), datagramname .. " - Len: " .. tvb2():len())
            subtree2:add(tvb2( 0, 1), "Id: 0x" .. tvb2( 0, 1))
            subtree2:add(tvb2( 1, 1), "Cmd: 0x" .. tvb2( 1, 1))
            subtree2:add(tvb2( 2, 3), "DeviceAddr: 0x" .. tvb2( 2, 3))
            subtree2:add(tvb2( 5, 3), "AppAddr: 0x" .. tvb2( 5, 3))
        end

    else

        local frameinfo = "unknown"
        local platform = "unknown"
        local datagramname = "Data"
        local rawData
        local rawDataOffset
        local rawDataLength
        local headerOffset
        local resultDataLength = 0


        -- Android
        if cada_Android_Identifier then

            rawDataOffset = advDataOffset + 7
            rawDataLength = 24
    		headerOffset = 15
    		platform = "Android"
            resultDataLength = 16

        -- iOS
        elseif cada_iOS_Identifier then

            rawDataOffset = advDataOffset + 5
            rawDataLength = 24
    		headerOffset = 13
    		platform = "iOS"
            resultDataLength = 16
            
        end

        local data = buffer(rawDataOffset,rawDataLength)
        rawData = CryptTools.DecryptRfPayload(SeedArray_CaDA, 3, resultDataLength, headerOffset, CTXValue1_CaDA, CTXValue2_CaDA, data:bytes())

        if rawData:get_index(0) == 0x75 then

            local command = rawData:get_index(1)
            
            if command == 0x10 then

        		datagramname = "Connect"

            elseif command == 0x13 then

        		datagramname = "Control"
                CaDATools.Decrypt(rawData, 7)

            else

        		datagramname = "unknown"
                
            end
        end

        frameinfo = platform .. " - " .. manufacturer .." - " .. datagramname
        pinfo.cols.info = frameinfo

        if tree and rawData then
            local tvb1 = ByteArray.tvb(data:bytes(), frameinfo)
            local subtree1 = tree:add(CaDADissector, tvb1(), platform .. " - " .. manufacturer .. " - Payload")
            subtree1:add(tvb1(), "Len: " .. tvb1():len())

            local tvb2 = ByteArray.tvb(rawData, frameinfo)
            local subtree2 = tree:add(CaDADissector, tvb2(), frameinfo)
            subtree2:add(tvb2(), datagramname .. " - Len: " .. tvb2():len())
            subtree2:add(tvb2( 0, 1), "Id: 0x" .. tvb2( 0, 1))
            subtree2:add(tvb2( 1, 1), "Cmd: 0x" .. tvb2( 1, 1))
            subtree2:add(tvb2( 2, 3), "DeviceAddr: 0x" .. tvb2( 2, 3))
            subtree2:add(tvb2( 5, 3), "AppAddr: 0x" .. tvb2( 5, 3))
            subtree2:add(tvb2( 8, 2), "Random: 0x" .. tvb2( 8, 2))
            subtree2:add(tvb2(10, 1), "Channel 1: 0x" .. tvb2(10, 1))
            subtree2:add(tvb2(11, 1), "Channel 2: 0x" .. tvb2(11, 1))
            subtree2:add(tvb2(12, 1), "Channel 3: 0x" .. tvb2(12, 1))
        end
    end
end

-- Register as a post-dissector; this will run for every frame.
register_postdissector(CaDADissector)


