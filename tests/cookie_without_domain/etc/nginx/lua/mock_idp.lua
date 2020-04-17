-- NOTE: The output of this mock IdP is *NOT* the same as that of a real IdP.

local config = require "saml.mock_idp.config"
local idp = require "saml.service_provider.idp"
local random = require "saml.service_provider.random"
local slaxml = require 'slaxml'

local args, err = ngx.req.get_uri_args()
if err ~= nil then
    ngx.log(ngx.ERR, err)
    ngx.exit(ngx.HTTP_BAD_REQUEST)
    return
end

local saml_req = idp.decode_base64_and_uncompress_request(args.SAMLRequest)
if saml_req == nil then
    ngx.exit(ngx.HTTP_BAD_REQUEST)
    return
end
-- ngx.say("Welcome to /mock-idp, SAMLRequest=" .. saml_req)
local relay_state = args.RelayState

local params = idp.take_parameters_from_request(saml_req)
params.audience = "https://sp.example.com/sso"
params.name_qualifier = "idp.example.com"
params.name_id = 'john-doe'
params.attribute_name = config.response.attribute_names[1]
params.attribute_value = 'john.doe@example.com'
params.assertion_id = function()
    return "_a" .. random.hex(16)
end
params.session_id = function()
    return "_s" .. random.hex(16)
end
params.response_id = function()
    return "_EXAMPLE_SSO_" .. random.uuid_v4()
end
local res = idp.generate_response(config.mock_idp.res_tmpl, params)

local signed_res, err = idp.sign_response(
		res,
		config.mock_idp.key,
		{config.response.idp_certificate},
		config.response.id_attr)
if err ~= nil then
    ngx.log(ngx.ERR, err)
    ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
    return
end

ngx.header['X-Destination'] = params['AssertionConsumerServiceURL']
ngx.print(ngx.encode_args({SAMLResponse=ngx.encode_base64(signed_res), RelayState=relay_state}))
