local jwt = require "resty.jwt"
local validators = require "resty.jwt-validators"

local _M = {}

local mt = { __index = _M }

-- Example token_obj in JSON:
-- {
--   "header": {
--     "typ":"JWT",
--     "alg":"HS256",
--     "kid": "key_2020_001_ZZZZZZZZZZZZZZZ"
--   },
--   "payload": {
--     "iss": "https://sp.example.com",
--     "aud": "https://sp.example.com",
--     "sub": "john-doe",
--     "mail": "john.doe@example.com",
--     "exp": 1586347800,
--     "nbf": 1586347500,
--     "jti": "XXXXXXXXXXXXXXXXXXXXXXXXXXX",
--   }
-- }

function _M.new(token_obj)
    return setmetatable(token_obj, mt)
end

function _M.sign(self, config)
    local key = config.keys[config.current_key_id]
    self.header = {
        typ = "JWT",
        alg = config.algorithm,
        kid = config.current_key_id,
    }
    return jwt:sign(key, self)
end

function _M.verify(config, token_str)
    local key_func = function(kid)
        return config.keys[kid]
    end
    local claim_spec = {
        __jwt = function(val, claim, jwt_json)
            return val.header ~= nil and val.header.alg == config.algorithm
        end,
        sub = validators.required(),
        exp = validators.required(validators.is_not_expired()),
        nbf = validators.required(validators.is_not_before()),
        mail = validators.required()
    }
    local jwt_obj = jwt:verify(key_func, token_str, claim_spec)
    if not jwt_obj.verified then
        return _M.new(jwt_obj), jwt_obj.reason
    end
    return _M.new(jwt_obj)
end

return _M
