local random = require "saml.service_provider.random"
local xmlsec = require 'saml.service_provider.xmlsec'
local slaxml = require 'slaxml'
local zlib = require "ffi-zlib"

local _M = {}

function _M.decode_base64_and_uncompress_request(request)
    local compressed_req = ngx.decode_base64(request)

    local i = 1
    local input = function(bufsize)
        if i > #compressed_req then
            return nil
        end
        local ret = string.sub(compressed_req, i, i + bufsize - 1)
        i = i + bufsize
        return ret
    end

    local output_table = {}
    local output = function(data)
        table.insert(output_table, data)
    end
    local ok, err = zlib.inflateGzip(input, output, nil, -15)
    if not ok then
        return nil, err
    end
    local saml_req = table.concat(output_table, '')
    return saml_req
end

function _M.take_parameters_from_request(request_xml)
    local onAuthnRequestElem = false
    local onIssuerElem = false
    local params = {}

    local handleStartElement = function(name, nsURI, nsPrefix)
        onAuthnRequestElem = (nsPrefix == "samlp" and name == "AuthnRequest")
        onIssuerElem = (nsPrefix == "saml" and name == "Issuer")
    end
    local handleAttribute = function(name, value, nsURI, nsPrefix)
        if onAuthnRequestElem then
            params[name] = value
        end
    end
    local handleText = function(text, cdata)
        if onIssuerElem then
            params['issuer'] = text
        end
    end

    local parser = slaxml:parser{
        startElement = handleStartElement,
        attribute = handleAttribute,
        text = handleText
    }
    parser:parse(request_xml, {stripWhitespace=true})
    return params
end

local function format_date(time)
    return os.date("!%Y-%m-%dT%H:%M:%SZ", time)
end

function _M.generate_response(res_tmpl, params)
    local request_id = params['ID']
    local idp_issuer = params['Destination']
    local sp_issuer = params['issuer']
    local destination = params['AssertionConsumerServiceURL']

    local audience = params.audience
    local name_qualifier = params.name_qualifier
    local name_id = params.name_id
    local attribute_name = params.attribute_name
    local attribute_value = params.attribute_value

    local assertion_id = params.assertion_id()
    local session_id = params.session_id()
    local response_id = params.response_id()

    local now_time = ngx.time()
    local now = format_date(now_time)
    local not_on_or_before = format_date(now_time - 5 * 60)
    local not_on_or_after = format_date(now_time + 5 * 60)
    local session_not_on_or_after = format_date(now_time + 24 * 60 * 60)

    local authn_context_class_ref = 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
    local nameid_format = 'urn:oasis:names:tc:SAML:1.1:nameid-format:persistent'

    local res = string.gsub(res_tmpl, "{{ request_id }}", request_id)
    res = string.gsub(res, "{{ response_id }}", response_id)
    res = string.gsub(res, "{{ assertion_id }}", assertion_id)
    res = string.gsub(res, "{{ session_id }}", session_id)

    res = string.gsub(res, "{{ idp_issuer }}", idp_issuer)
    res = string.gsub(res, "{{ sp_issuer }}", sp_issuer)
    res = string.gsub(res, "{{ destination }}", destination)
    res = string.gsub(res, "{{ audience }}", audience)

    res = string.gsub(res, "{{ now }}", now)
    res = string.gsub(res, "{{ not_on_or_before }}", not_on_or_before)
    res = string.gsub(res, "{{ not_on_or_after }}", not_on_or_after)
    res = string.gsub(res, "{{ session_not_on_or_after }}", session_not_on_or_after)

    res = string.gsub(res, '{{ authn_context_class_ref }}', authn_context_class_ref)
    res = string.gsub(res, '{{ nameid_format }}', nameid_format)
    res = string.gsub(res, '{{ name_qualifier }}', name_qualifier)
    res = string.gsub(res, '{{ name_id }}', name_id)

    -- NOTE: We support only one attribute here.
    res = string.gsub(res, '{{ key }}', attribute_name)
    res = string.gsub(res, '{{ value }}', attribute_value)
    res = string.gsub(res, '      {%% for key, value in attributes.items %%}\n', '')
    res = string.gsub(res, '      {%% endfor %%}\n', '')

    return res
end

function _M.sign_response(response_xml, key, certificates, id_attr)
    return xmlsec.sign_response(response_xml, key, certificates, id_attr)
end

return _M
