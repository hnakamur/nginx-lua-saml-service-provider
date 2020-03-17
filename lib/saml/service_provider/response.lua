-- Copyright (C) by Hiroaki Nakamura (hnakamur)

local slaxml = require 'slaxml'
local setmetatable = setmetatable

local _M = { _VERSION = '0.1.1' }

local mt = { __index = _M }

function _M.new(self, config)
    return setmetatable({
        xmlsec_command = config.xmlsec_command,
        idp_cert_filename = config.idp_cert_filename
    }, mt)
end

function _M.read_and_base64decode_response(self)
    ngx.req.read_body()
    local args, err = ngx.req.get_post_args()
    if err ~= nil then
       return nil, string.format("failed to get post args to read SAML response, err=%s", err)
    end

    return ngx.decode_base64(args.SAMLResponse)
end

function _M.verify_response(self, response_xml)
    local tmpfilename = os.tmpname()
    local file, err = io.open(tmpfilename, "w")
    if err ~= nil then
       return false, string.format("failed to open temporary file for writing SAML response, err=%s", err)
    end
    file:write(response_xml)
    file:close()

    local cmd = string.format("%s --verify --pubkey-cert-pem %s --id-attr:ID urn:oasis:names:tc:SAML:2.0:protocol:Response %s",
        self.xmlsec_command, self.idp_cert_filename, tmpfilename)
    local code = os.execute(cmd)
    if code ~= 0 then
       return false, string.format("failed to verify SAML response, exitcode=%d", code)
    end

    local ok, err = os.remove(tmpfilename)
    if not ok then
       return false, string.format("failed to delete SAML response tmpfile, filename=%s, err=%s", tmpfilename, err)
    end
    return true
end

function _M.take_attributes_from_response(self, response_xml)
    local onAttributeElemStart = false
    local inAttributeElem = false
    local inAttributeValueElem = false
    local attrs = {}
    local attr_name = nil

    local handleStartElement = function(name, nsURI, nsPrefix)
        if nsPrefix == "saml" and name == "Attribute" then
            onAttributeElemStart = true
            inAttributeElem = true
        else
            onAttributeElemStart = false
        end
        if nsPrefix == "saml" and name == "AttributeValue" then
            inAttributeValueElem = true
        end
    end
    local handleAttribute = function(name, value, nsURI, nsPrefix)
        if onAttributeElemStart and name == "Name" then
            attr_name = value
        end
    end
    local handleCloseElement = function(name, nsURI)
        if nsPrefix == "saml" and name == "Attribute" then
            inAttributeElem = false
        end
        if nsPrefix == "saml" and name == "AttributeValue" then
            inAttributeValueElem = false
        end
    end

    local handleText = function(text)
        if inAttributeValueElem then
            attrs[attr_name] = text
        end
    end
    local parser = slaxml:parser{
        startElement = handleStartElement,
        attribute = handleAttribute,
        closeElement = handleCloseElement,
        text = handleText
    }
    parser:parse(response_xml, {stripWhitespace=true})
    return attrs
end

function _M.take_request_id_from_response(self, response_xml)
    local onResponseElement = false
    local request_id = nil

    local handleStartElement = function(name, nsURI, nsPrefix)
        if nsPrefix == "samlp" and name == "Response" then
            onResponseElement = true
        else
            onResponseElement = false
        end
    end
    local handleAttribute = function(name, value, nsURI, nsPrefix)
        if onResponseElement and name == "InResponseTo" then
            request_id = value
        end
    end
    local parser = slaxml:parser{
        startElement = handleStartElement,
        attribute = handleAttribute
    }
    parser:parse(response_xml, {stripWhitespace=true})
    return request_id
end

return _M
