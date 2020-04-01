-- Copyright (C) by Hiroaki Nakamura (hnakamur)

local ffi = require("ffi")
local ffi_new = ffi.new
local ffi_str = ffi.string
local C = ffi.C

ffi.cdef[[
int RAND_bytes(unsigned char *buf, int num);
]]

local _M = {}

function _M.bytes(len)
    local buf = ffi_new("char[?]", len)
    if C.RAND_bytes(buf, len) == 0 then
        return nil
    end

    return ffi_str(buf, len)
end

function _M.to_hex(bytes)
    local h = string.gsub(bytes, "(.)", function(c)
        return string.format("%02x", string.byte(c))
    end)
    return h
end

function _M.hex(byte_length)
    return _M.to_hex(_M.bytes(byte_length))
end

function _M.uuid_v4()
    local random = _M.bytes(16)
    local c7 = string.char(bit.bor(bit.band(
        string.byte(string.sub(random, 7, 7)), 0x0F), 0x40))
    local c9 = string.char(bit.bor(bit.band(
        string.byte(string.sub(random, 9, 9)), 0x3F), 0x80))
    return _M.to_hex(string.sub(random, 1, 4)) ..  "-" ..
           _M.to_hex(string.sub(random, 5, 6)) .. "-" ..
           _M.to_hex(c7) ..  _M.to_hex(string.sub(random, 8, 8)) .. "-" ..
           _M.to_hex(c9) ..  _M.to_hex(string.sub(random, 10, 16))
end

return _M
