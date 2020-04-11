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
    -- local dict = self.dict
    -- -- NOTE: The time resoution for shared dict is 0.001 second.
    -- -- https://github.com/openresty/lua-nginx-module#ngxshareddictset
    -- local minimum_exptime = 0.001
    -- for i = 1, config.issue_max_retry_count do
    --     local id = config.prefix .. random.hex(config.random_byte_len)
    --     local expire_seconds = expire_seconds_func()
    --     if expire_seconds < minimum_exptime then
    --         return nil, 'issue_id: expired before issueing'
    --     end
    --     local success, err, forcible = dict:add(id, value, expire_seconds)
    --     if success then
    --         ngx.log(ngx.INFO, 'shdict_store.issue_id id=', id, ', value=', value, ', expire_seconds=', expire_seconds)
    --         return id
    --     elseif err ~= "exists" then
    --         return nil, string.format('issue_id: err=%s, forcible=%s', err, forcible)
    --     end
    -- end
    return nil, 'issue_id: exceeded max_retry_count'
end

function _M.take_uri_before_login(self, request_id, exptime)
    -- local dict = self.dict
    -- -- local dict = ngx.shared[self.dict_name]
    -- local uri_before_login, err = dict:get(request_id)
    -- if err ~= nil or uri_before_login == '' then
    --     -- Already finished login, this is replay attack.
    --     return nil, false, err
    -- end

    -- -- NOTE: We MUST keep used request_id until not_on_or_after
    -- -- because it is needed by the SAML spec.
    -- --
    -- -- Document identifier: saml-profiles-2.0-os
    -- -- Location: http://docs.oasis-open.org/security/saml/v2.0/
    -- --
    -- -- 4.1.4.5 POST-Specific Processing Rules
    -- -- The service provider MUST ensure that bearer assertions are not replayed,
    -- -- by maintaining the set of used ID values for the length of time for which
    -- -- the assertion would be considered valid based on the NotOnOrAfter attribute
    -- -- in the <SubjectConfirmationData>.
    -- if exptime > 0 then
    --     local success, err, forcible = dict:replace(request_id, '', exptime)
    --     if not success then
    --         return nil, false,
    --             string.format("empty uri_before_login for request_id, dict=%s, request_id=%s, err=%s, forcible=%s",
    --                           self.dict_name, request_id, err, forcible)
    --     end
    -- else
    --     dict:delete(request_id)
    -- end
    -- return uri_before_login, true, nil
end

--- Use nonce
-- @param self          shared dict store (object).
-- @param nonce         nonce (string).
-- @param config        config (table).
-- @return allowed      (bool)
-- @return first_use    (bool)
-- @return err          (string or nil)
function _M.use_nonce(self, nonce, config)
    -- local dict = self.dict
    -- local count, err, forcible = dict:incr(nonce, -1)
    -- if err ~= nil then
    --     return false, false, string.format('dict:incr: %s', err)
    -- end
    -- if count == config.usable_count - 1 then
    --     local success, err = dict:expire(nonce, config.duration_after_first_use_seconds)
    --     if not success then
    --         return false, false, string.format('dict:expire: %s', err)
    --     end
    --     return true, true, nil
    -- end
    -- return count >= 0, false, nil
end

function _M.delete_id(self, id)
    -- local dict = self.dict
    -- local success, err, forcible = dict:delete(id)
    -- if not success then
    --     return string.format('delete_id: err=%s, forcible=%s', err, forcible)
    -- end
    -- ngx.log(ngx.INFO, 'shdict_store.delete_id id=', id)
    -- return nil
end

return _M
