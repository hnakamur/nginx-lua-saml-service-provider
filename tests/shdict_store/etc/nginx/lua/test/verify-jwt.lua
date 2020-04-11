local saml_sp_access_token = require('saml.service_provider.access_token')
local config = require "saml.service_provider.config"
local cjson = require('cjson.safe')

ngx.req.read_body()
local signed_token = ngx.req.get_body_data()
local token = saml_sp_access_token.verify(config.test.access_token, signed_token)
ngx.print(cjson.encode(token))
