-- Copyright (C) by Hiroaki Nakamura (hnakamur)

local zlib = require "ffi-zlib"
local evp = require "resty.evp"
local setmetatable = setmetatable

local _M = {}

local mt = { __index = _M }

function _M.new(request_id, config)
    return setmetatable({
        request_id = request_id,
        idp_dest_url = config.idp_dest_url,
        sp_entity_id = config.sp_entity_id,
        sp_saml_finish_url = config.sp_saml_finish_url,
        sp_private_key = config.sp_private_key,
    }, mt)
end

function _M.redirect_to_idp_to_login(self)
    local req, err = self:create_compress_base64encode_request()
    if err ~= nil then
        return nil, err
    end

    if self.sp_private_key == nil then
        local url = self.idp_dest_url .. "?" .. ngx.encode_args{SAMLRequest = req}
        return ngx.redirect(url)
    else
        -- sign the SAMLRequest to authenticate service provider at IdP
        -- NOTE: Only RSA-SHA256 signature is accepted.
        local req_encoded = ngx.encode_args{SAMLRequest = req}
        local alg_encoded = ngx.encode_args{SigAlg = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"}
        local hash_input = req_encoded .. "&" .. alg_encoded
        local signer, err  = evp.RSASigner:new(self.sp_private_key)
        if not signer then
            ngx.log(ngx.ERR, err)
            return nil, err
        end
        local signature = signer:sign(hash_input, evp.CONST.SHA256_DIGEST)
        local sig_encoded = ngx.encode_args{Signature = ngx.encode_base64(signature)}
        local url = self.idp_dest_url .. "?" .. req_encoded .. "&" .. alg_encoded .. "&" .. sig_encoded
        return ngx.redirect(url)
    end
end

function _M.create_compress_base64encode_request(self)
    local request_xml = self:create_request_xml()
    local compressed, err = self:compress(request_xml)
    if err ~= nil then
        return nil, err
    end

    return ngx.encode_base64(compressed)
end

function _M.create_request_xml(self)
    local now = ngx.utctime()
    local issue_instant = string.sub(now, 1, #"yyyy-mm-dd") .. "T" .. string.sub(now, -#"hh:mm:ss") .. "Z"

    return string.format(
        [[<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" AssertionConsumerServiceURL="%s" Destination="%s" ID="%s" IssueInstant="%s" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Version="2.0">
<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">%s</saml:Issuer>
<samlp:NameIDPolicy AllowCreate="1"/>
</samlp:AuthnRequest>]],
        self.sp_saml_finish_url,
        self.idp_dest_url,
        self.request_id,
        issue_instant,
        self.sp_entity_id
    )
end

function _M.compress(self, request_xml)
    local i = 1
    local input = function(bufsize)
        if i > #request_xml then
            return nil
        end
        local ret = string.sub(request_xml, i, i + bufsize - 1)
        i = i + bufsize
        return ret
    end

    local output_table = {}
    local output = function(data)
        table.insert(output_table, data)
    end

    local options = {windowBits = 15}
    local ok, err = zlib.deflateGzip(input, output, nil, options)
    if not ok then
        return nil, string.format("failed to compress SAML request, err=%s", err)
    end

    local compressed = string.sub(table.concat(output_table, ''), 2 + 1, -(4 + 1))
    return compressed, nil
end

return _M
