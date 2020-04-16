local access_token = require('saml.service_provider.access_token')
local config = require "saml.service_provider.config"
local cjson = require('cjson.safe')

ngx.req.read_body()
local signed_token = ngx.req.get_body_data()

local cfg = {}
for k, v in pairs(config.test.access_token) do
    cfg[k] = v
end
cfg['iss'] = config.request.sp_entity_id
cfg['aud'] = config.request.sp_entity_id
cfg['required_keys'] = {'sub', 'mail'}
if ngx.var.http_disable_all_keys ~= nil then
   cfg.keys = {}
end

local token, err = access_token.verify(cfg, signed_token)
if err ~= nil then
    -- NOTE: For custom error page output, we have to set ngx.status and
    -- call return ngx.exit(ngx.HTTP_OK).
    -- https://github.com/openresty/lua-nginx-module#ngxexit
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.header['X-Verify-Error'] = err
    ngx.print(cjson.encode(token))
    return ngx.exit(ngx.HTTP_OK)
end
ngx.print(cjson.encode(token))
