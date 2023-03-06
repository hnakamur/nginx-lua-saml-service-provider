(function()

local xmlsec = require "saml.service_provider.xmlsec"
local config = require "saml.service_provider.config"
config.response.idp_certificate = xmlsec.readfile('/etc/nginx/saml/idp.example.com.crt')
config.request.sp_private_key = xmlsec.readfile('/etc/ssl/private/sp.example.com.key')
xmlsec.load_xsd_files('/etc/nginx/saml')

end)()
