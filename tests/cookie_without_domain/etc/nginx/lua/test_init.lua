ngx.log(ngx.INFO, 'test_init.lua start')

;(function()

local random = require "saml.service_provider.random"
local config = require "saml.service_provider.config"

local key_id = 'key_2020_001_' .. random.hex(16)
config.test = {
    access_token = {
        algorithm = 'HS256',
        current_key_id = key_id,
        keys = {
            [key_id] = random.hex(16),
        },
    }
}

end)()

ngx.log(ngx.INFO, 'test_init.lua end')
