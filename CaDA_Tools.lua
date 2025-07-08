-- CaDATools.lua

-- Load Wireshark’s built-in bit operations
local band   = bit.band
local bor    = bit.bor
local bxor   = bit.bxor
local lshift = bit.lshift
local rshift = bit.rshift

-- CaDATools-Modul
local CaDATools = {}

local SwitchSheet = {
  0xf4, 0xa8, 0xa0, 0x8c, 0x28, 0xec, 0x44, 0x00,
  0x6c, 0x48, 0x24, 0x98, 0xd4, 0x9c, 0x0c, 0xac,
  0xa4, 0xbc, 0xcc, 0x80, 0x38, 0xe8, 0x5c, 0x1c,
  0x94, 0xb0, 0xc8, 0x54, 0x34, 0x08, 0x74, 0xf0,
  0xdc, 0x14, 0xc4, 0xc0, 0x50, 0x18, 0x64, 0x7c,
  0x70, 0x78, 0x88, 0x90, 0x58, 0x2c, 0xf8, 0x84,
  0x30, 0x68, 0x60, 0x04, 0x40, 0x4c, 0xe0, 0xb8,
  0xd8, 0xfc, 0x20, 0x10, 0xe4, 0x3c, 0xd0, 0xb4,
}


-- Decrypts an 8-byte array (1-based Lua table data[offset + 1]..data[offset + 8])
function CaDATools.Decrypt(data, offset)
  -- 1) Reverse the SwitchSheet substitution
  for idx = 1, 8 do
    local val = data:get_index(offset + idx)
    for orig = 0, 255 do
      local base = SwitchSheet[math.floor(orig/4) + 1]
      if base + (orig % 4) == val then
        data:set_index(offset + idx, orig)
        break
      end
    end
  end

  -- 2) Reverse the XOR with data[offset + 2] and constant 0x69 (for bytes 3..8)
  for i = 3, 8 do
    data:set_index(offset + i, bxor(data:get_index(offset + i), data:get_index(offset + 2), 0x69))
  end

  -- 3) Reverse the bit-level shuffles in reverse order
  local d0 = data:get_index(offset + 1)

  if band(d0, 0x80) ~= 0 then
    local saved_4 = data:get_index(offset + 4)
    local saved_3 = data:get_index(offset + 3)
    data:set_index(offset + 4, band(bor(band(saved_4, 0xf0), rshift(band(saved_3, 0xf0), 4)), 0xff))
    data:set_index(offset + 3, band(bor(band(saved_3, 0x0f), lshift(band(saved_4, 0x0f), 4)), 0xff))
  end

  if band(d0, 0x40) ~= 0 then
    local saved_4 = data:get_index(offset + 4)
    local saved_3 = data:get_index(offset + 3)
    data:set_index(offset + 4, band(bor(band(saved_4, 0x0f), lshift(band(saved_3, 0x0f), 4)), 0xff))
    data:set_index(offset + 3, band(bor(band(saved_3, 0xf0), rshift(band(saved_4, 0xf0), 4)), 0xff))
  end

  if band(d0, 0x20) ~= 0 then
    local saved_8 = data:get_index(offset + 8)
    local saved_7 = data:get_index(offset + 7)
    data:set_index(offset + 8, band(bor(band(saved_8, 0xf0), rshift(band(saved_7, 0xf0), 4)), 0xff))
    data:set_index(offset + 7, band(bor(band(saved_7, 0x0f), lshift(band(saved_8, 0x0f), 4)), 0xff))
  end

  if band(d0, 0x10) ~= 0 then
    local saved_8 = data:get_index(offset + 8)
    local saved_6 = data:get_index(offset + 6)
    data:set_index(offset + 8, band(bor(band(saved_8, 0x0f), band(saved_6, 0xf0)), 0xff))
    data:set_index(offset + 6, band(bor(band(saved_6, 0x0f), band(saved_8, 0xf0)), 0xff))
  end

  if band(d0, 0x08) ~= 0 then
    local saved_5 = data:get_index(offset + 5)
    local saved_4 = data:get_index(offset + 5)
    data:set_index(offset + 5, band(bor(band(saved_5, 0xf0), rshift(band(saved_4, 0xf0), 4)), 0xff))
    data:set_index(offset + 4, band(bor(band(saved_4, 0x0f), lshift(band(saved_5, 0x0f), 4)), 0xff))
  end

  if band(d0, 0x04) ~= 0 then
    local saved_5 = data:get_index(offset + 5)
    local saved_4 = data:get_index(offset + 4)
    data:set_index(offset + 5, band(bor(band(saved_5, 0x0f), lshift(saved_4, 4)), 0xff))
    data:set_index(offset + 4, band(bor(band(saved_4, 0xf0), rshift(band(saved_5, 0xf0), 4)), 0xff))
  end

  if band(d0, 0x02) ~= 0 then
    local saved_6 = data:get_index(offset + 6)
    local saved_3 = data:get_index(offset + 3)
    data:set_index(offset + 6, band(bor(band(saved_6, 0xf0), rshift(band(saved_3, 0xf0), 4)), 0xff))
    data:set_index(offset + 3, band(bor(band(saved_3, 0x0f), lshift(band(saved_6, 0x0f), 4)), 0xff))
  end

  if band(d0, 0x01) ~= 0 then
    local saved_7 = data:get_index(offset + 7)
    local saved_3 = data:get_index(offset + 3)
    data:set_index(offset + 7, band(bor(band(saved_7, 0xf0), band(saved_3, 0x0f)), 0xff))
    data:set_index(offset + 3, band(bor(band(saved_3, 0xf0), band(saved_7, 0x0f)), 0xff))
  end
end

return CaDATools