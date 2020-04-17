-- Copyright (C) by Hiroaki Nakamura (hnakamur)

local session_cookie = require "session.cookie"
local saml_sp_request = require "saml.service_provider.request"
local saml_sp_response = require "saml.service_provider.response"
local random = require "saml.service_provider.random"
local time = require "saml.service_provider.time"
local access_token = require "saml.service_provider.access_token"
local cjson = require "cjson.safe"
local xmlsec = require "saml.service_provider.xmlsec"

local setmetatable = setmetatable

local _M = { _VERSION = '0.9.0' }

local mt = { __index = _M }

function _M.new(self, config)
    return setmetatable({
        config = config
    }, mt)
end

function _M._relay_state_verify_cfg(self)
    local cfg = {}
    for k, v in pairs(self.config.session.jwt_sign) do
        cfg[k] = v
    end
    cfg['iss'] = self.config.request.sp_entity_id
    cfg['aud'] = self.config.request.sp_entity_id
    cfg['required_keys'] = {'request_id', 'redirect_uri'}
    return cfg
end

function _M._take_and_verify_relay_state(self)
    local rsc = self:request_cookie()
    local signed_state, err = rsc:get()
    ngx.log(ngx.DEBUG, 'signed_state=', signed_state, ', err=', err)
    if err ~= nil then
        return nil, err
    end
    local ok, err = rsc:set("{}")
    if err ~= nil then
        return nil, nil, string.format('clear request_cookie: %s', err)
    end

    local cfg = self:_relay_state_verify_cfg()
    local state, err = access_token.verify(cfg, signed_state)
    return state, err
end

function _M._access_token_verify_cfg(self)
    local cfg = {}
    for k, v in pairs(self.config.session.jwt_sign) do
        cfg[k] = v
    end
    cfg['iss'] = self.config.request.sp_entity_id
    cfg['aud'] = self.config.request.sp_entity_id
    cfg['required_keys'] = {'sub'}
    return cfg
end

function _M._get_and_verify_token(self)
    local session_cookie = self:session_cookie()
    local signed_token, err = session_cookie:get()
    ngx.log(ngx.DEBUG, 'signed_token=', signed_token, ', err=', err)
    if err ~= nil then
        return nil, err
    end

    local cfg = self:_access_token_verify_cfg()
    local token, err = access_token.verify(cfg, signed_token)
    return token, err
end

function _M.issue_id(config)
    return config.prefix .. random.hex(config.random_byte_len)
end

function _M.access(self)
    local allowed
    local token, err = self:_get_and_verify_token()
    if err ~= nil then
        ngx.log(ngx.WARN, err)
    else
        allowed = true
    end
    if err ~= nil or not allowed then
        -- NOTE: uri_before_login can be long so we store it
        -- in request_cookie instead of setting it to RelayState.
        --
        -- Document identifier: saml-bindings-2.0-os
        -- Location: http://docs.oasis-open.org/security/saml/v2.0/
        -- 3.4.3 RelayState
        -- The value MUST NOT exceed 80 bytes in length
        local uri_before_login = ngx.var.uri .. ngx.var.is_args .. (ngx.var.args ~= nil and ngx.var.args or "")
        local req_id_cfg = self.config.request.id
        local request_id = _M.issue_id(req_id_cfg)

        local jwt_id  = _M.issue_id(self.config.session.jwt_id)
        local iss = self.config.request.sp_entity_id
        local aud = iss
        local now = ngx.time()
        local relay_state = access_token.new{
            payload = {
                iss = iss,
                aud = aud,
                request_id = request_id,
                redirect_uri = uri_before_login,
                exp = now + req_id_cfg.expire_seconds,
                nbf = now,
                jti = jwt_id,
            }
        }
        local sign_cfg = self.config.session.jwt_sign
        local signed_state = relay_state:sign(sign_cfg)

        local rsc = self:request_cookie()
        local ok, err = rsc:set(signed_state)
        if err ~= nil then
            ngx.log(ngx.ERR, err)
            return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
        end

        local sp_req = self:request()
        return sp_req:redirect_to_idp_to_login(request_id)
    end

    for _, name in ipairs(self.config.response.attribute_names) do
        ngx.req.set_header(name, token.payload[name])
    end
    ngx.req.set_header('name-id', token.payload.sub)
    return nil
end

function _M.finish_login(self)
    local sp_resp = self:response()

    local response_xml, err = sp_resp:read_and_base64decode_response()
    if err ~= nil then
        ngx.log(ngx.WARN, err)
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end

    local ok, err = sp_resp:verify_response_memory(response_xml)
    if err ~= nil then
        ngx.log(ngx.WARN, err)
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
    if not ok then
        ngx.log(ngx.WARN, 'SAMLResponse verify failed')
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end

    local vals = sp_resp:take_values_from_response(response_xml)

    local state, err = self:_take_and_verify_relay_state()
    if err ~= nil then
        ngx.log(ngx.WARN, err)
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
    local request_id = state.payload.request_id
    local redirect_uri = state.payload.redirect_uri
    ngx.log(ngx.DEBUG, 'req_id_in_cookie=', request_id, ', redirect_uri=', redirect_uri)
    if request_id ~= vals.request_id then
        ngx.log(ngx.WARN, string.format('request_id unmatch, req_id_in_cookie=%s, req_id_in_saml_resp=%s', request_id, vals.request_id))
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end

    local req_expire_timestamp, err = time.parse_iso8601_utc_time(vals.not_on_or_after)
    if err ~= nil then
        -- Malicious date value attack.
        ngx.log(ngx.WARN, err)
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
    local req_exptime = req_expire_timestamp - ngx.time()

    local session_expire_timestamp, err = time.parse_iso8601_utc_time(vals.session_not_on_or_after)
    if err ~= nil then
        -- Malicious date value attack.
        ngx.log(ngx.WARN, err)
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end

    local jwt_id  = _M.issue_id(self.config.session.jwt_id)
    local iss = self.config.request.sp_entity_id
    local aud = iss
    local token = access_token.new{
        payload = {
            iss = iss,
            aud = aud,
            sub = vals.name_id,
            exp = session_expire_timestamp,
            nbf = ngx.time(),
            jti = jwt_id,
        }
    }
    for _, name in ipairs(self.config.response.attribute_names) do
        token.payload[name] = vals.attrs[name]
    end
    local sign_cfg = self.config.session.jwt_sign
    local signed_token = token:sign(sign_cfg)
    local sc = self:session_cookie()
    local ok, err = sc:set(signed_token)
    if err ~= nil then
        ngx.log(ngx.ERR, err)
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end

    return ngx.redirect(redirect_uri)
end

function _M.logout(self)
    local token, err = self:_get_and_verify_token()
    if err ~= nil then
        ngx.log(ngx.WARN, 'logout: get and verify token: ', err)
    else
        -- In ideal, we would delete the cookie by setting expiration to
        -- the Unix epoch date.
        -- In reality, curl still sends the cookie after receiving
        -- the Unix epoch date
        -- with set-cookie, so we have to change the cookie value instead
        -- of deleting it.
        local sc = self:session_cookie()
        local ok, err = sc:set("{}")
        if err ~= nil then
            ngx.log(ngx.ERR, 'logout: set cookie to empty: ', err)
        end
    end
    return ngx.redirect(self.config.logout.redirect_url)
end


function _M.request(self)
    local request = self._request
    if request ~= nil then
        return request
    end

    local config = self.config.request
    request = saml_sp_request:new{
        idp_dest_url = config.idp_dest_url,
        sp_entity_id = config.sp_entity_id,
        sp_saml_finish_url = config.sp_saml_finish_url,
    }
    self._request = request
    return request
end

function _M.response(self)
    local response = self._response
    if response ~= nil then
        return response
    end

    response = saml_sp_response:new(self.config.response)
    self._response = response
    return response
end

function _M.session_cookie(self)
    local config = self.config.session.cookie
    return session_cookie:new(config)
end

function _M.request_cookie(self)
    local config = self.config.request.cookie
    return session_cookie:new(config)
end

return _M
