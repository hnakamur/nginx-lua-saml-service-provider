local session_store = require "session.store"
local random = require "saml.service_provider.random"

local _M = {}

local mt = { __index = _M }

--- Creates shared dict session store manager.
-- @param config        The config (table).
function _M.new(self, config)
    local dict_name = config.shared_dict_name
    if dict_name == nil then
        ngx.log(ngx.EMEG, 'shared_dict_name must be defined in config')
    end
    local dict = ngx.shared[dict_name]
    if dict == nil then
        ngx.log(ngx.EMEG, string.format('shared dict not defined, dict_name=%s', dict_name))
    end

    return setmetatable({
        dict = dict,
        dict_name = dict_name,
        request_id_expire_seconds = config.request_id_expire_seconds or 300,
        request_id_prefix = config.request_id_prefix or '_',
        request_id_random_byte_len = config.request_id_random_byte_len or 16,
        session_store = session_store:new{
            dict_name = dict_name,
            id_generator = function()
                return random.hex(config.session_id_byte_length or 16)
            end
        }
    }, mt)
end

function _M.issue_request_id(self, uri_before_login)
    local dict = self.dict
    local request_id, success, err, forcible
    repeat
        request_id = self.request_id_prefix .. random.hex(self.request_id_random_byte_len)
        success, err, forcible = dict:add(request_id, uri_before_login, self.request_id_expire_seconds)
    until success or err ~= "exists"
    if not success then
        return nil,
            string.format("error to add uri_before_login, dict=%s, request_id=%s, err=%s, forcible=%s",
                          self.dict_name, request_id, err, forcible)
    end
    return request_id
end

function _M.take_uri_before_login(self, request_id, exptime)
    local dict = self.dict
    -- local dict = ngx.shared[self.dict_name]
    local uri_before_login, err = dict:get(request_id)
    if err ~= nil or uri_before_login == '' then
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
        local success, err, forcible = dict:set(request_id, '', exptime)
        if not success then
            return nil, false,
                string.format("empty uri_before_login for request_id, dict=%s, request_id=%s, err=%s, forcible=%s",
                              self.dict_name, request_id, err, forcible)
        end
    else
        dict:delete(request_id)
    end
    return uri_before_login, true, nil
end

--- Store the attribute value and issue session ID.
-- @param attr_val      The attribute value (string).
-- @param exptime       The timestamp for expiration (number).
-- @return the issued session ID (string).
-- @return err (string or nil).
function _M.store(self, attr_val, exptime)
    local duration = exptime - ngx.now()
    local session_id, err = self.session_store:add(attr_val, duration)
    if err ~= nil then
        return "",
            string.format("failed to add attribute to shared dict, err=%s", err)
    end
    return session_id, nil
end

--- Retrieve the attribute value related to session_id
-- @param session_id    The session id (string).
-- @return the attribute value (string or nil).
function _M.retrieve(self, session_id)
    if session_id == nil or session_id == "" then
        return nil
    end
    return self.session_store:get(session_id)
end

--- Delete the attribute related to session_id from the shared dict.
-- @param session_id    The session id (string).
function _M.delete(self, session_id)
    self.session_store:delete(session_id)
end

return _M
