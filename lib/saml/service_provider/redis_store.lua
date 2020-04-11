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
    elseif cfg.domain_socket ~= nil then
	    ok, err = red:connect(cfg.domain_socket, cfg.connect_options)
    end
	if not ok then
        ngx.log(ngx.EMERG, 'connect redis: ', err)
        return nil
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

function _M.issue_id(self, value, expire_seconds_func, config)
    local red = self.red
    for i = 1, config.issue_max_retry_count do
        local id = config.prefix .. random.hex(config.random_byte_len)
        local expire_seconds = expire_seconds_func()
        if expire_seconds <= 0 then
            return nil, 'issue_id: expired before issueing'
        end
        local ok, err = red:set(id, value, 'EX', expire_seconds, 'NX')
        if not ok then
            ngx.log(ngx.ERR, 'redis:set: ', err, ', id=', id, ', value=', value, ', expire_seconds=', expire_seconds)
            return nil, err
        elseif ok ~= ngx.null then
            return id
        end
    end
    return nil, 'issue_id: exceeded max_retry_count'
end

function _M.take_uri_before_login(self, request_id, exptime)
    local red = self.red
    ngx.log(ngx.INFO, 'before redis:get: request_id=', request_id)
    local uri_before_login, err = red:get(request_id)
    if err ~= nil or uri_before_login == ngx.null or uri_before_login == '' then
        ngx.log(ngx.ERR, 'redis:get: err=', err, ', uri_before_login=', uri_before_login)
        -- Already finished login, this is replay attack.
        return nil, false, err
    end

    -- NOTE: We MUST keep used request_id until not_on_or_after
    -- because it is needed by the SAML spec.
    --
    -- Document identifier: saml-profiles-2.0-os
    -- Location: http://docs.oasis-open.org/security/saml/v2.0/
    --
    -- 4.1.4.5 POST-Specific Processing Rules
    -- The service provider MUST ensure that bearer assertions are not replayed,
    -- by maintaining the set of used ID values for the length of time for which
    -- the assertion would be considered valid based on the NotOnOrAfter attribute
    -- in the <SubjectConfirmationData>.
    if exptime > 0 then
        local ok, err = red:set(request_id, '', 'EX', exptime, 'XX')
        if not ok then
            ngx.log(ngx.ERR, 'redis:set: ', err, ', request_id=', request_id, ', exptime=', exptime)
            return nil, false, err
        end
    else
        local ok, err = red:del(request_id)
        if not ok then
            ngx.log(ngx.ERR, 'redis:delete: ', err)
            return nil, false, err
        end
    end
    return uri_before_login, true, nil
end

--- Use nonce
-- @param self          shared dict store (object).
-- @param nonce         nonce (string).
-- @param config        config (table).
-- @return allowed      (bool)
-- @return first_use    (bool)
-- @return err          (string or nil)
function _M.use_nonce(self, nonce, config)
    local red = self.red
    local count, err = red:incrby(nonce, -1)
    if err ~= nil then
        ngx.log(ngx.ERR, 'redis:incrby: ', err)
        return false, false, err
    end
    if count == config.usable_count - 1 then
        local ok, err = red:expire(nonce, config.duration_after_first_use_seconds)
        if not ok then
            ngx.log(ngx.ERR, 'redis:expire: ', err)
            return false, false, err
        end
        return true, true, nil
    end
    return count >= 0, false, nil
end

function _M.delete_id(self, id)
    local red = self.red
    local ok, err = red:del(request_id)
    if not ok then
        ngx.log(ngx.ERR, 'redis:del: ', err)
        return err
    end
    return nil
end

return _M
