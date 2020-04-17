-- Copyright (C) by Hiroaki Nakamura (hnakamur)

local ffi = require "ffi"
local slaxml = require 'slaxml'
local xmlsec = require "saml.service_provider.xmlsec"
local setmetatable = setmetatable

local _M = {}

local mt = { __index = _M }

--- Creates a SAML response verifier object.
-- @param response_xml        response_xml (string).
-- @param config              configuration options (table).
--
-- config.idp_certificate     IdP certificate (string).
-- config.id_attr             ID attribute (table with "attrName", "nodeName",
--                            and "nsHref" keys).
--                            Example:
--                            { attrName = "ID", nodeName = "Response",
--                              nsHref = "urn:oasis:names:tc:SAML:2.0:protocol" }
-- @return a SAML response verifier object.
function _M.new(response_xml, config)
    return setmetatable({
        response_xml = response_xml,
        idp_certificate = config.idp_certificate,
        id_attr = config.id_attr
    }, mt)
end

--- Read and base64 decode a SAML response from the request body.
-- @return a decoded SAML response.
-- @return err.
function _M.read_and_base64decode_response()
    ngx.req.read_body()
    local args, err = ngx.req.get_post_args()
    if err ~= nil then
        ngx.log(ngx.WARN, 'ngx.req.get_post_args: ', err)
        return nil, 'read_and_base64decode_response: ngx.req.get_post_args'
    end
    -- NOTE: Long args.SAMLResponse will be truncated in nginx log without "..." suffix.
    ngx.log(ngx.DEBUG, "args.SAMLResponse=", args.SAMLResponse)

    local saml_resp = ""
    -- NOTE: We guard here to avoid error called in ngx.decode_base64.
    if type(args.SAMLResponse) == 'string' then
        saml_resp = ngx.decode_base64(args.SAMLResponse)
    end
    if saml_resp == "" then
        ngx.log(ngx.WARN, 'ngx.decode_base64 SAMLResponse=', args.SAMLResponse)
        return nil, 'read_and_base64decode_response: ngx.decode_base64'
    end
    ngx.log(ngx.DEBUG, "saml_resp=", saml_resp)
    return saml_resp
end

--- Verifies a simple SAML response on memory.
-- In addition to refular verification we ensure that the signature
-- has only one <dsig:Reference/> element.
--
-- @param self           a SAML response.
-- @return ok            verified successfully or not (bool).
-- @return err           the error message (string or nil).
function _M.verify(self)
    return xmlsec.verify_response(self.response_xml, self.idp_certificate, self.id_attr)
end

--- Take values from a SAML response.
-- @param self            a SAML response.
-- @return values (table).
function _M.take_values(self)
    local wantsNameID = false
    local name_id

    local onSubjectConfirmationDataElem = false
    local request_id
    local not_on_or_after

    local onAuthnStatementElement = false
    local session_not_on_or_after = nil

    local onAttributeElem = false
    local wantsAttrVal = false
    local attrs = {}
    local attr_name

    local handleStartElement = function(name, nsURI, nsPrefix)
        if nsPrefix == "saml" then
            wantsNameID = (name == "NameID")
            onSubjectConfirmationDataElem = (name == "SubjectConfirmationData")
            onAuthnStatementElement = (name == "AuthnStatement")
            onAttributeElem = (name == "Attribute")
            wantsAttrVal = (name == "AttributeValue")
        end
    end
    local handleAttribute = function(name, value, nsURI, nsPrefix)
        if onSubjectConfirmationDataElem then
            if name == "InResponseTo" then
                request_id = value
            elseif name == "NotOnOrAfter" then
                not_on_or_after = value
            end
        end
        if onAuthnStatementElement and name == "SessionNotOnOrAfter" then
            session_not_on_or_after = value
        end
        if onAttributeElem and name == "Name" then
            attr_name = value
        end
    end
    local handleText = function(text)
        if wantsNameID then
            name_id = text
            wantsNameID = false
        end
        if wantsAttrVal then
           attrs[attr_name] = text
           wantsAttrVal = false
        end
    end
    local parser = slaxml:parser{
        startElement = handleStartElement,
        attribute = handleAttribute,
        text = handleText
    }
    parser:parse(self.response_xml, {stripWhitespace=true})
    return {
        name_id = name_id,
        request_id = request_id,
        not_on_or_after = not_on_or_after,
        session_not_on_or_after = session_not_on_or_after,
        attrs = attrs,
    }
end

return _M
