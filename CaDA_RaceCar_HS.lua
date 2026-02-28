-- Define a new protocol for post-dissector usage.
local CaDADissector = Proto("CaDA_HS", "Global Frame Analyzer for Bluetooth LE from CaDA - Type HS")

function CaDADissector.dissector(buffer, pinfo, tree)

    -- check protocol string
	if not tostring(pinfo.cols.protocol) == "LE LL" then
		return 0
	end

	local length = buffer:len()

    -- advertisingdata starts here
    local advDataOffset = 29

    local cada_Device_Response = 
        length == 63 and
        buffer(advDataOffset + 0,  1):uint() == 0x11 and -- Length: 17
        buffer(advDataOffset + 1,  1):uint() == 0xff and -- type: Manufacturer Specific (0xff) 
        buffer(advDataOffset + 2,  1):uint() == 0xaa and -- Company Id 0x11aa
        buffer(advDataOffset + 3,  1):uint() == 0x11 and
        buffer(advDataOffset + 4,  1):uint() == 0x11 and -- CaDA identifier
        true                                             -- enabled

    local cada_Android_Identifier = 
        length == 55 and
        buffer(advDataOffset +  3, 1):uint() == 0x13 and -- Length: 19
        buffer(advDataOffset +  4, 1):uint() == 0xff and -- type: Manufacturer Specific (0xff) 
        buffer(advDataOffset +  5, 1):uint() == 0x00 and -- Company Id 0xc200
        buffer(advDataOffset +  6, 1):uint() == 0xc2 and -- 
        -- buffer(advDataOffset +  7, 1):uint() == 0xbb and -- 0xbb (command) or 0x 0xaa (connect)
        buffer(advDataOffset +  8, 1):uint() == 0x11 and -- header: 0x11
        buffer(advDataOffset +  9, 1):uint() == 0x11 and -- 
        -- buffer(advDataOffset + 10, 1):uint() == 0xc9 and -- device id 0xc1c9
        -- buffer(advDataOffset + 11, 1):uint() == 0xc1 and -- 
        -- buffer(advDataOffset + 12, 1):uint() == 0x79 and -- app id 0x2979
        -- buffer(advDataOffset + 13, 1):uint() == 0x29 and -- 
        -- buffer(advDataOffset + 14, 1):uint() == 0x00 and -- aa - trottle
        -- buffer(advDataOffset + 15, 1):uint() == 0x00 and -- bb - steering
        -- buffer(advDataOffset + 16, 1):uint() == 0x00 and -- cc - lights
        -- buffer(advDataOffset + 17, 1):uint() == 0x00 and -- dd - offset
        -- buffer(advDataOffset + 18, 1):uint() == 0x00 and -- ee - sequence id
        buffer(advDataOffset + 19, 1):uint() == 0xcc and -- footer 0xcc
        buffer(advDataOffset + 20, 1):uint() == 0xb8 and -- footer 0xb8
        buffer(advDataOffset + 21, 1):uint() == 0x92 and -- footer 0x92
        -- buffer(advDataOffset + 22, 1):uint() == 0xb0 and -- footer 0xb0 (command) or 0x 0xa0 (connect)
        true                                              -- enabled

    local cada_iOS_Identifier =
        length == 63 and
        buffer(advDataOffset +  3,  1):uint() == 0x1b and -- Length: 27
        buffer(advDataOffset +  4,  1):uint() == 0x03 and -- type: Complete List of 16-bit Service Class UUIDs (0x03)
        buffer(advDataOffset +  5,  1):uint() == 0xc0 and -- CaDA identifier 0xc000
        buffer(advDataOffset +  6,  1):uint() == 0x00 and
        -- buffer(advDataOffset +  7,  1):uint() == 0xbb and -- 0xbb (command) or 0x 0xaa (connect)
        buffer(advDataOffset +  8,  1):uint() == 0x11 and -- header: 0x11
        buffer(advDataOffset +  9,  1):uint() == 0x11 and --
        -- buffer(advDataOffset + 10,  1):uint() == 0xc9 and -- device id 0xc1c9
        -- buffer(advDataOffset + 11,  1):uint() == 0xc1 and --
        -- buffer(advDataOffset + 12,  1):uint() == 0x17 and -- app id 0xc117
        -- buffer(advDataOffset + 13,  1):uint() == 0x7f and --
        -- buffer(advDataOffset + 14,  1):uint() == 0xe4 and -- aa - trottle
        -- buffer(advDataOffset + 15,  1):uint() == 0xe4 and -- bb - steering
        -- buffer(advDataOffset + 16,  1):uint() == 0x00 and -- cc - lights
        -- buffer(advDataOffset + 17,  1):uint() == 0x64 and -- dd - offset
        -- buffer(advDataOffset + 18,  1):uint() == 0xa1 and -- ee - sequence id
        buffer(advDataOffset + 19,  1):uint() == 0xcc and -- footer 0xcc 
        buffer(advDataOffset + 20,  1):uint() == 0xb8 and -- footer 0xb8
        buffer(advDataOffset + 21,  1):uint() == 0x92 and -- footer 0x92
        -- buffer(advDataOffset + 22,  1):uint() == 0xb0 and -- footer 0xb0 (command) or 0x 0xa0 (connect)
        -- buffer(advDataOffset + 23,  1):uint() == 0xef and -- 
        -- buffer(advDataOffset + 24,  1):uint() == 0xf2 and -- 
        -- buffer(advDataOffset + 25,  1):uint() == 0xc5 and -- 
        -- buffer(advDataOffset + 26,  1):uint() == 0x67 and -- 
        -- buffer(advDataOffset + 27,  1):uint() == 0x8f and -- 
        -- buffer(advDataOffset + 28,  1):uint() == 0x9f and -- 
        -- buffer(advDataOffset + 29,  1):uint() == 0xf1 and -- 
        -- buffer(advDataOffset + 30,  1):uint() == 0xf8 and -- 
        true                                              -- enabled

    if not (cada_Device_Response or cada_Android_Identifier or cada_iOS_Identifier) then 
		return 0
	end

    local manufacturer = "CaDA HS"

    if cada_Device_Response then

        local rawDataOffset = advDataOffset + 4
        local rawDataLength = 14
        local platform = "Device"

        datagramname = "Response"

        local frameinfo = platform .. " - " .. manufacturer .." - " .. datagramname
        pinfo.cols.info = frameinfo
     
        local rawData = buffer(rawDataOffset, rawDataLength):bytes()

        if tree and rawData then
            local tvb2 = ByteArray.tvb(rawData, frameinfo)
            local subtree2 = tree:add(CaDADissector, tvb2(), frameinfo)
            subtree2:add(tvb2(), datagramname .. " - Len: " .. tvb2():len())
            subtree2:add(tvb2( 1, 2), "App Id: 0x" .. tvb2( 2, 1) .. tvb2( 1, 1))
            subtree2:add(tvb2( 3, 2), "Device ID: 0x" .. tvb2( 4, 1) .. tvb2( 3, 1))
        end

    else

        local platform = "unknown"
        local rawDataOffset
        local rawDataLength

        -- Android
        if cada_Android_Identifier then

            rawDataOffset = advDataOffset + 7
            rawDataLength = 16
    		platform = "Android"

        -- iOS
        elseif cada_iOS_Identifier then

            rawDataOffset = advDataOffset + 7
            rawDataLength = 16
    		platform = "iOS"
            
        end

        local rawdata = buffer(rawDataOffset, rawDataLength)

        local command = rawdata(0, 1):uint()
        
        if command == 0xaa then

            local datagramname = "Connect"

            local frameinfo = platform .. " - " .. manufacturer .." - " .. datagramname
            pinfo.cols.info = frameinfo

            if tree then
                local tvb1 = ByteArray.tvb(rawdata:bytes(), frameinfo)
                local subtree1 = tree:add(CaDADissector, tvb1(), platform .. " - " .. manufacturer .. " - Payload")
                subtree1:add(tvb1(), "Len: " .. tvb1():len())

                local tvb2 = ByteArray.tvb(rawdata:bytes(), frameinfo)
                local subtree2 = tree:add(CaDADissector, tvb2(), frameinfo)
                subtree2:add(tvb2(), datagramname .. " - Len: " .. tvb2():len())
                subtree2:add(tvb2( 0, 1), "Cmd: 0x" .. tvb2( 0, 1))
                subtree2:add(tvb2( 1, 1), "Id: 0x" .. tvb2( 1, 1))
                subtree2:add(tvb2( 2, 1), "Id: 0x" .. tvb2( 2, 1))
                subtree2:add(tvb2( 3, 2), "Device Id: 0x" .. tvb2( 4, 1) .. tvb2( 3, 1))
                subtree2:add(tvb2( 5, 2), "App Id: 0x" .. tvb2( 6, 1) .. tvb2( 5, 1))
                -- subtree2:add(tvb2( 7, 1), "Throttle: 0x" .. tvb2( 7, 1))
                -- subtree2:add(tvb2( 8, 1), "Steering: 0x" .. tvb2( 8, 1))
                -- subtree2:add(tvb2( 9, 1), "Lights: 0x" .. tvb2( 9, 1))
                -- subtree2:add(tvb2(10, 1), "Offset: 0x" .. tvb2(10, 1))
                subtree2:add(tvb2(11, 1), "Sequence Id: 0x" .. tvb2(11, 1))
            end                
        elseif command == 0xbb then
            local seqId_RAW = rawdata(11, 1)
            local seqId = seqId_RAW:uint() & 0xff
            local seqIdName = string.format("%03d", seqId) .. "[0x" .. string.format("%02x", seqId) .. "]"

            local offset_RAW = rawdata(10, 1)
            local offset = offset_RAW:int() & 0xff
            local offsetString =  string.format("%03d", offset) .. "[0x" .. string.format("%02x", offset) .. "]"

            local throttle_RAW = rawdata(7, 1)
            local throttle = -(((throttle_RAW:int() & 0xff) ~ offset) - 0x80)
            local throttleString = string.format("%4d", throttle) .. "[0x" .. string.format("%02x", throttle & 0xff) .. "]"

            local steering_RAW = rawdata(8, 1)
            local steering = ((steering_RAW :int() & 0xff) ~ offset) - 0x80
            local steeringString = string.format("%4d", steering) .. "[0x" .. string.format("%02x", steering & 0xff) .. "]"

            local lights_RAW = rawdata(9, 1)
            local lights = lights_RAW:int()
            local lightsString = lights .. "[0x" .. string.format("%x", lights) .. "]"

            local datagramname = "Control Seq=" .. seqIdName .. " O=" .. offsetString .. " T=" .. throttleString .. " S=" .. steeringString .. " L=" .. lightsString

            local frameinfo = platform .. " - " .. manufacturer .." - " .. datagramname
            pinfo.cols.info = frameinfo

            if tree then
                local tvb1 = ByteArray.tvb(rawdata:bytes(), frameinfo)
                local subtree1 = tree:add(CaDADissector, tvb1(), platform .. " - " .. manufacturer .. " - Payload")
                subtree1:add(tvb1(), "Len: " .. tvb1():len())

                local tvb2 = ByteArray.tvb(rawdata:bytes(), frameinfo)
                local subtree2 = tree:add(CaDADissector, tvb2(), frameinfo)
                subtree2:add(tvb2(), datagramname .. " - Len: " .. tvb2():len())
                subtree2:add(tvb2( 0, 1), "Cmd: 0x" .. tvb2( 0, 1))
                subtree2:add(tvb2( 1, 1), "Id: 0x" .. tvb2( 1, 1))
                subtree2:add(tvb2( 2, 1), "Id: 0x" .. tvb2( 2, 1))
                subtree2:add(tvb2( 3, 2), "Device Id: 0x" .. tvb2( 4, 1) .. tvb2( 3, 1))
                subtree2:add(tvb2( 5, 2), "App Id: 0x" .. tvb2( 6, 1) .. tvb2( 5, 1))
                subtree2:add(tvb2( 7, 1), "Throttle: " .. throttleString)
                subtree2:add(tvb2( 8, 1), "Steering: " .. steeringString)
                subtree2:add(tvb2( 9, 1), "Lights: " .. lightsString)
                subtree2:add(tvb2(10, 1), "Offset: 0x" .. tvb2(10, 1))
                subtree2:add(tvb2(11, 1), "Sequence Id: 0x" .. tvb2(11, 1))
            end

        else

        end
    end
end

-- Register as a post-dissector; this will run for every frame.
register_postdissector(CaDADissector)


