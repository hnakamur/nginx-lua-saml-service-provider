-- Copyright (C) by Hiroaki Nakamura (hnakamur)

local resty_random = require "resty.random"
local str = require "resty.string"

local _M = {}

function _M.hex(length, strong)
    local random = resty_random.bytes(length, strong)
    return str.to_hex(random)
end

function _M.uuid_v4(strong)
    local random = resty_random.bytes(16, strong)
    local c7 = string.char(bit.bor(bit.band(
        string.byte(string.sub(random, 7, 7)), 0x0F), 0x40))
    local c9 = string.char(bit.bor(bit.band(
        string.byte(string.sub(random, 9, 9)), 0x3F), 0x80))
    return str.to_hex(string.sub(random, 1, 4)) ..  "-" ..
           str.to_hex(string.sub(random, 5, 6)) .. "-" ..
           str.to_hex(c7) ..  str.to_hex(string.sub(random, 8, 8)) .. "-" ..
           str.to_hex(c9) ..  str.to_hex(string.sub(random, 10, 16))
end

return _M
