local cjson = require('cjson.safe')
local jwt = require "resty.jwt"
local validators = require "resty.jwt-validators"

local _M = {}

local mt = { __index = _M }

-- {
--   "header": {"typ":"JWT", "alg":"HS256"},
--   "payload": {
--     "kid": "key_2020_001_ZZZZZZZZZZZZZZZ",
--     "iss": "https://sp.example.com",
--     "aud": "https://sp.example.com",
--     "sub": "john-doe",
--     "mail": "john.doe@example.com",
--     "exp": 1586347800,
--     "nbf": 1586347500,
--     "jti": "XXXXXXXXXXXXXXXXXXXXXXXXXXX",
--     "nonce": "YYYYYYYYYYYYYYYYYYY"
--   }
-- }

function _M.new(obj)
    return setmetatable(obj, mt)
end

function _M.decode(str)
    return _M.new(cjson.decode(str))
end

function _M.encode(self)
    return cjson.encode(self)
end

function _M.sign(self, config)
    local key = config.keys[config.current_key_id]
    return jwt:sign(
        key,
        {
            header={typ="JWT", alg=config.algorithm},
            payload=self
        }
    )
end

function _M.verify(config, token_str)
    local key = config.keys[config.current_key_id]
    local claim_spec = {
        __jwt = function(val, claim, jwt_json)
            return val.header ~= nil and val.header.alg == config.algorithm
        end,
        -- exp = validators.required(validators.opt_is_not_expired()),
        mail = validators.required()
    }
    return jwt:verify(key, token_str, claim_spec)
end

-- jwt_sign = {
--     algorithm = 'HS256',
--     current_key_id = 'key_2020_001_cea3cd1220254c3914b3012db9707894',
--     keys = {
--         ['key_2020_001_cea3cd1220254c3914b3012db9707894'] = 'Ny5qaJJDXNMjOr+MFFnJoM1LSKr+5F5T',
--     },
-- },

--function _M.verify(self, jwt_token)
--    local claim_spec = {
--        __jwt = function(val, claim, jwt_json)
--            return val.header ~= nil and val.header.alg == self.algorithm
--        end,
--        exp = validators.required(validators.opt_is_not_expired()),
--        mail = validators.required()
--    }
--    return jwt:verify(self.symmetric_key, jwt_token, claim_spec)
--end
--
--function _M.sign(self, payload)
--    return jwt:sign(
--        self.symmetric_key,
--        {
--            header={typ="JWT", alg=self.algorithm},
--            payload=payload
--        }
--    )
--end

return _M
