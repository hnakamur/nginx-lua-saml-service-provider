local jwt = require "resty.jwt"
local validators = require "resty.jwt-validators"

local _M = {}

function _M.verify(config, jwt_token)
    local claim_spec = {
        __jwt = function(val, claim, jwt_json)
            return val.header ~= nil and val.header.alg == config.algorithm
        end,
        exp = validators.required(validators.opt_is_not_expired()),
        mail = validators.required()
    }
    return jwt:verify(config.symmetric_key, jwt_token, claim_spec)
end

function _M.sign(config, payload)
    return jwt:sign(
        config.symmetric_key,
        {
            header={typ="JWT", alg=config.algorithm},
            payload=payload
        }
    )
end

return _M
