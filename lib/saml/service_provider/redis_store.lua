local redis = require "resty.redis"
local random = require "saml.service_provider.random"

local _M = {}

local mt = { __index = _M }

--- Creates shared dict session store manager.
-- @param config        The config (table).
function _M.new(self, config)
    local cfg = config.redis

	local red = redis:new()
	red:set_timeouts(
        cfg.connect_timeout_seconds * 1000,
        cfg.send_timeout_seconds * 1000,
        cfg.read_timeout_seconds * 1000)

	local ok, err
    if cfg.host ~= nil then
	    ok, err = red:connect(cfg.host, cfg.port, cfg.connect_options)
        if not ok then
            ngx.log(ngx.EMERG, 'connect redis: ', err,
                ', host=', cfg.host, ', port=', cfg.port)
            return nil
        end
    elseif cfg.domain_socket ~= nil then
	    ok, err = red:connect(cfg.domain_socket, cfg.connect_options)
            ngx.log(ngx.EMERG, 'connect redis: ', err,
                ', domain_socket=', cfg.domain_socket)
    end

    return setmetatable({
        config = config,
        red = red
    }, mt)
end

function _M.close(self)
    local red = self.red
    local cfg = self.config.redis
    local ok, err = red:set_keepalive(
        cfg.connection_pool_keepalive_seconds * 1000,
        cfg.connection_pool_size)
    if not ok then
        ngx.log(ngx.EMERG, 'put back to redis connection pool: ', err)
        return
    end
end

function _M.ensure_not_replayed(self, request_id, expire_seconds)
    local red = self.red
    local ok, err = red:set(request_id, '', 'EX', expire_seconds, 'NX')
    if not ok then
        ngx.log(ngx.WARN, string.format('ensure_not_replayed request_id=%s, expire_seconds=%d, err=%s', request_id, expire_seconds, err))
    end
    return ok
end

return _M
