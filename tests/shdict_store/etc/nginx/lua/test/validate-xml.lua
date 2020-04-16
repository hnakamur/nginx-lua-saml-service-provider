local ffi = require("ffi")
local xml2 = ffi.load("xml2")
local xmlsec = require('saml.service_provider.xmlsec')

ngx.req.read_body()
local res_xml = ngx.req.get_body_data()
local doc = xml2.xmlParseDoc(res_xml);
local ok = xmlsec.validateXMLWithSchemaDoc(doc)
if not ok then
    return ngx.exit(ngx.HTTP_BAD_REQUEST)
end
ngx.print('OK')
