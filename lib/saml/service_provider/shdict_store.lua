local random = require "saml.service_provider.random"

local _M = {}

local mt = { __index = _M }

--- Creates shared dict session store manager.
-- @param config        The config (table).
function _M.new(self, config)
    local dict_name = config.shared_dict_name
    if dict_name == nil then
        ngx.log(ngx.EMERG, 'shared_dict_name must be defined in config')
    end
    local dict = ngx.shared[dict_name]
    if dict == nil then
        ngx.log(ngx.EMERG, string.format('shared dict not defined, dict_name=%s', dict_name))
    end

    return setmetatable({
        dict = dict,
        dict_name = dict_name,
    }, mt)
end

function _M.close(self)
    -- This is no-op for shdict_store
end

function _M.ensure_not_replayed(self, request_id, expire_seconds)
    local dict = self.dict
    local success, err, forcible = dict:add(request_id, '', expire_seconds)
    if err ~= nil then
        ngx.log(ngx.WARN, string.format('ensure_not_replayed request_id=%s, expire_seconds=%d, err=%s, forcible=%s', request_id, expire_seconds, err, forcible))
    end
    return success
end

return _M
