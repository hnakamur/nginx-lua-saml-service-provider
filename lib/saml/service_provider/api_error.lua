local _M = { }

local mt = { __index = _M }

function _M.new(self, attrs)
    return setmetatable({
        err_code = attrs.err_code,
        status_code = attrs.status_code or ngx.HTTP_INTERNAL_SERVER_ERROR,
        log_level = attrs.log_level or ngx.ERR,
        log_detail = attrs.log_detail
    }, mt)
end

return _M
