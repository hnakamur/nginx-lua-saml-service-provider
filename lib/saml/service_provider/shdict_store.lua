local session_store = require "session.store"
local random = require "saml.service_provider.random"

local _M = {}

local mt = { __index = _M }

--- Creates shared dict session store manager.
-- @param config        The config (table).
-- @return a shared dict session store manager (object).
function _M.new(self, config)
    return setmetatable({
        session_store = session_store:new{
            dict_name = config.dict_name,
            id_generator = function()
                return random.hex(config.session_id_byte_length or 16)
            end
        }
    }, mt)
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
