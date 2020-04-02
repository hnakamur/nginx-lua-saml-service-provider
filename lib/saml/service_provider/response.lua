-- Copyright (C) by Hiroaki Nakamura (hnakamur)

local ffi = require "ffi"
local slaxml = require 'slaxml'
local xmlsec = require "saml.service_provider.xmlsec"
local setmetatable = setmetatable

local _M = {}

local mt = { __index = _M }

--- Creates a SAML response verifier object.
-- @param config              configuration options (table).
--
-- config.idp_certificate     IdP certificate (string).
-- config.id_attr             ID attribute (table with "attrName", "nodeName",
--                            and "nsHref" keys).
--                            Example:
--                            { attrName = "ID", nodeName = "Response",
--                              nsHref = "urn:oasis:names:tc:SAML:2.0:protocol" }
-- Deprecated keys:
-- config.xmlsec_command      the filename of xmlsec1 command.
-- config.idp_cert_filename   the filename of IdP certificate.
-- @return a SAML response verifier object.
function _M.new(self, config)
    return setmetatable({
        xmlsec_command = config.xmlsec_command,
        idp_cert_filename = config.idp_cert_filename,
        idp_certificate = config.idp_certificate,
        id_attr = config.id_attr
    }, mt)
end

--- Read and base64 decode a SAML response from the request body.
-- @param self a SAML response veirifier.
-- @return a decoded SAML response.
-- @return RelayState parameter.
-- @return err.
function _M.read_and_base64decode_response(self)
    ngx.req.read_body()
    local args, err = ngx.req.get_post_args()
    if err ~= nil then
       return nil, nil, string.format("failed to get post args to read SAML response, err=%s", err)
    end
    -- NOTE: Long args.SAMLResponse will be truncated in nginx log without "..." suffix.
    ngx.log(ngx.DEBUG, "args.SAMLResponse=", args.SAMLResponse)
    -- NOTE: Long args.RelayState will be truncated in nginx log without "..." suffix.
    ngx.log(ngx.DEBUG, "args.RelayState=", args.RelayState)

    return ngx.decode_base64(args.SAMLResponse), args.RelayState
end

--- Verifies a SAML response with xmlsec1 command (Deprecated).
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

--- Take attributes from a SAML response.
-- @param self            a SAML response veirifier.
-- @param response_xml    a SAML response (string).
-- @return attributes (table).
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

--- Take the request ID from a SAML response.
-- @param self            a SAML response veirifier.
-- @param response_xml    a SAML response (string).
-- @return the request ID (string).
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

--- Take the session expiration time from a SAML response.
-- @param self            a SAML response veirifier.
-- @param response_xml    a SAML response (string).
-- @return the session expiration time (string).
function _M.take_session_expiration_time_from_response(self, response_xml)
    local onAuthnStatementElement = false
    local exptime = nil

    local handleStartElement = function(name, nsURI, nsPrefix)
        onAuthnStatementElement = (nsPrefix == "saml" and name == "AuthnStatement")
    end
    local handleAttribute = function(name, value, nsURI, nsPrefix)
        if onAuthnStatementElement and name == "SessionNotOnOrAfter" then
            exptime = value
        end
    end
    local parser = slaxml:parser{
        startElement = handleStartElement,
        attribute = handleAttribute
    }
    parser:parse(response_xml, {stripWhitespace=true})
    return exptime
end

--- Verifies a simple SAML response on memory.
-- In addition to refular verification we ensure that the signature
-- has only one <dsig:Reference/> element.
--
-- @param self           a SAML response verifier.
-- @param response_xml   response XML (string).
-- @return err           nil if verified successfully, the error message otherwise (string).
function _M.verify_response_memory(self, response_xml)
    return xmlsec.verify_response(response_xml, self.idp_certificate, self.id_attr)
end

return _M
