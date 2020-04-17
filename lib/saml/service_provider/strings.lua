local _M = {}

function _M.has_prefix(s, prefix)
    return #s >= #prefix and string.sub(s, 1, #prefix) == prefix
end

return _M
