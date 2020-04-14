ngx.log(ngx.INFO, 'mock_idp_init.lua start')

;(function()

local xmlsec = require "saml.service_provider.xmlsec"
local config = require "saml.mock_idp.config"
config.response.idp_certificate = xmlsec.readfile('/etc/nginx/saml/idp.example.com.crt')

config.mock_idp = {
    key      = xmlsec.readfile('/etc/nginx/saml/idp.example.com.key'),
    res_tmpl = xmlsec.readfile('/etc/nginx/saml/mock-idp-res-tmpl.xml')
}

end)()

ngx.log(ngx.INFO, 'mock_idp_init.lua end')
