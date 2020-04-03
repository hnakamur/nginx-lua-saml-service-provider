local jwt = require "resty.jwt"
local validators = require "resty.jwt-validators"

local _M = {}

local mt = { __index = _M }

-- NOTE: The name and signature for the following methods must be same as that in shdict_store.
-- * new
-- * store
-- * retrieve
-- * delete

--- Creates JWT access token store manager.
-- @param config        The config (table).
-- @return a JWT access token store manager (object).
function _M.new(self, config)
    return setmetatable({
        key_attr_name = config.key_attr_name,
        symmetric_key = config.symmetric_key,
        algorithm = config.algorithm
    }, mt)
end

--- Create and sign JWT.
-- @param attr_val      The attribute value (string).
-- @param exptime       The timestamp for expiration (number).
-- @return the created and signed JWT (string).
function _M.store(self, attr_val, exptime)
    local payload = {
        [self.key_attr_name] = attr_val,
        exp = exptime,
    }
    return self:sign(payload)
end

--- Verify JWT and retrieve the attribute value.
-- @param jwt_token     The JWT.
-- @return the attribute value (string or nil).
-- @return err (string or nil).
function _M.retrieve(self, jwt_token)
    local verified_jwt, err = self:verify(jwt_token)
    if err ~= nil then
        return nil, err
    end
    if not verified_jwt.verified then
        return nil, nil
    end
    return verified_jwt.payload[self.key_attr_name], nil
end

--- This method is no-op for JWT access token store manager.
-- @param jwt_token     The JWT.
function _M.delete(self, jwt_token)
end

function _M.verify(self, jwt_token)
    local claim_spec = {
        __jwt = function(val, claim, jwt_json)
            return val.header ~= nil and val.header.alg == self.algorithm
        end,
        exp = validators.required(validators.opt_is_not_expired()),
        mail = validators.required()
    }
    return jwt:verify(self.symmetric_key, jwt_token, claim_spec)
end

function _M.sign(self, payload)
    return jwt:sign(
        self.symmetric_key,
        {
            header={typ="JWT", alg=self.algorithm},
            payload=payload
        }
    )
end

return _M
