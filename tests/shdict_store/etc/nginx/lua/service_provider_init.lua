ngx.log(ngx.INFO, 'service_provider_init.lua start')

;(function()

local xmlsec = require "saml.service_provider.xmlsec"
local config = require "saml.service_provider.config"
config.response.idp_certificate = xmlsec.readfile('/etc/nginx/saml/idp.example.com.crt')
xmlsec.load_xsd_files('/etc/nginx/saml')

end)()

ngx.log(ngx.INFO, 'service_provider_init.lua end')
