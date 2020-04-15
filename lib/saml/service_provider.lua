-- Copyright (C) by Hiroaki Nakamura (hnakamur)

local session_cookie = require "session.cookie"
local saml_sp_request = require "saml.service_provider.request"
local saml_sp_response = require "saml.service_provider.response"
local random = require "saml.service_provider.random"
local time = require "saml.service_provider.time"
local redis_store = require "saml.service_provider.redis_store"
local shdict_store = require "saml.service_provider.shdict_store"
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

function _M._get_and_verify_token(self)
    local session_cookie = self:session_cookie()
    local signed_token, err = session_cookie:get()
    ngx.log(ngx.DEBUG, '_get_and_verify_token signed_token=', signed_token, ', err=', err)
    if err ~= nil then
        return nil, err
    end

    local verify_cfg = self.config.session.store.jwt_sign
    local token, err = access_token.verify(verify_cfg, signed_token)
    -- ngx.log(ngx.DEBUG, '_get_and_verify_token after verify, token=', cjson.encode(token))
    -- ngx.log(ngx.DEBUG, '_get_and_verify_token verify err=', err)
    return token, err
end

function _M.access(self)
    local ss = self:session_store()
    local ret = (function()
        local allowed
        local token, err = self:_get_and_verify_token()
        if err ~= nil then
            ngx.log(ngx.WARN, err)
        else
            local nonce = token.payload.nonce
            local nonce_cfg = self.config.session.store.jwt_nonce
            local first_use
            allowed, first_use, err = ss:use_nonce(nonce, nonce_cfg)
            if err ~= nil then
                ngx.log(ngx.WARN, err)
            end
            if first_use then
                local session_expire_timestamp = token.payload.exp
                local session_expire_seconds_func = function()
                    return session_expire_timestamp - ngx.time()
                end
                local new_nonce, err = ss:issue_id(nonce_cfg.usable_count,
                    session_expire_seconds_func, nonce_cfg)
                if err ~= nil then
                    ngx.log(ngx.ERR, err)
                end
                local new_token = access_token.new{
                    payload = token.payload
                }
                new_token.payload.nonce = new_nonce

                local sign_cfg = self.config.session.store.jwt_sign
                local signed_token = new_token:sign(sign_cfg)
                local sc = self:session_cookie()
                local ok
                ok, err = sc:set(signed_token)
                if err ~= nil then
                    ngx.log(ngx.ERR, err)
                end
            end
        end
        if err ~= nil or not allowed then
            -- NOTE: uri_before_login can be long so we store it in shared dict
            -- instead of setting it to RelayState.
            --
            -- Document identifier: saml-bindings-2.0-os
            -- Location: http://docs.oasis-open.org/security/saml/v2.0/
            -- 3.4.3 RelayState
            -- The value MUST NOT exceed 80 bytes in length
            local uri_before_login = ngx.var.uri .. ngx.var.is_args .. (ngx.var.args ~= nil and ngx.var.args or "")
            local cfg = self.config.session.store.request_id
            local expire_seconds_func = function()
                return cfg.expire_seconds
            end
            local request_id, err = ss:issue_id(uri_before_login, expire_seconds_func, cfg)
            if err ~= nil then
                ngx.log(ngx.ERR, err)
            end
            local sp_req = self:request()
            return sp_req:redirect_to_idp_to_login(request_id)
        end


        local name_id = token.payload.sub
        local key_attr_name = self.config.key_attribute_name
        local key_attr = token.payload[key_attr_name]
        ngx.req.set_header('name-id', name_id)
        ngx.req.set_header(key_attr_name, key_attr)
        return nil
    end)()
    ss:close()
    return ret
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

    local req_expire_timestamp, err = time.parse_iso8601_utc_time(vals.not_on_or_after)
    if err ~= nil then
        -- Malicious date value attack.
        ngx.log(ngx.WARN, err)
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
    local req_exptime = req_expire_timestamp - ngx.time()

    local ss = self:session_store()
    local ret = (function()
        local redirect_uri, ok, err = ss:take_uri_before_login(vals.request_id, req_exptime)
        if err ~= nil or not ok then
            ngx.log(ngx.WARN, err)
            return ngx.exit(ngx.HTTP_FORBIDDEN)
        end

        local key_attr_name = self.config.key_attribute_name
        local key_attr = vals.attrs[key_attr_name]
        if key_attr == nil then
            ngx.log(ngx.WARN, 'key_attr not found in SAMLResponse')
            return ngx.exit(ngx.HTTP_FORBIDDEN)
        end

        local session_expire_timestamp, err = time.parse_iso8601_utc_time(vals.session_not_on_or_after)
        if err ~= nil then
            -- Malicious date value attack.
            ngx.log(ngx.WARN, err)
            return ngx.exit(ngx.HTTP_FORBIDDEN)
        end
        local session_expire_seconds_func = function()
            return session_expire_timestamp - ngx.time()
        end

        local jwt_id, err = ss:issue_id('', session_expire_seconds_func,
            self.config.session.store.jwt_id)
        if err ~= nil then
            ngx.log(ngx.ERR, err)
            return ngx.exit(ngx.HTTP_FORBIDDEN)
        end

        local nonce_cfg = self.config.session.store.jwt_nonce
        local nonce, err = ss:issue_id(nonce_cfg.usable_count, session_expire_seconds_func,
            nonce_cfg)
        if err ~= nil then
            ngx.log(ngx.ERR, err)
            return ngx.exit(ngx.HTTP_FORBIDDEN)
        end

        local iss = self.config.request.sp_entity_id
        local aud = iss
        local token = access_token.new{
            payload = {
                iss = iss,
                aud = aud,
                sub = vals.name_id,
                mail = key_attr,
                exp = session_expire_timestamp,
                nbf = ngx.time(),
                jti = jwt_id,
                nonce = nonce
            }
        }
        local sign_cfg = self.config.session.store.jwt_sign
        local signed_token = token:sign(sign_cfg)
        local sc = self:session_cookie()
        local ok, err = sc:set(signed_token)
        if err ~= nil then
            ngx.log(ngx.ERR, err)
            return ngx.exit(ngx.HTTP_FORBIDDEN)
        end

        return ngx.redirect(redirect_uri)
    end)()
    ss:close()
    return ret
end

function _M.logout(self)
    local sc = self:session_cookie()
    local ss = self:session_store()
    local ret = (function()
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
            local ok, err = sc:set("")
            if err ~= nil then
                ngx.log(ngx.ERR, 'logout: set cookie to empty: ', err)
            end

            local jwt_id = token.payload.jti
            err = ss:delete_id(jwt_id)
            if err ~= nil then
                ngx.log(ngx.ERR, 'logout: delete jwt_id: ', err)
            end

            local nonce = token.payload.nonce
            err = ss:delete_id(nonce)
            if err ~= nil then
                ngx.log(ngx.ERR, 'logout: delete nonce: ', err)
            end
        end
        return ngx.redirect(self.config.redirect.url_after_logout)
    end)()
    ss:close()
    return ret
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
        request_id_generator = function()
            return "_" .. random.hex(config.request_id_byte_length or 16)
        end
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
    local cookie = self._session_cookie
    if cookie ~= nil then
        return cookie
    end

    local config = self.config.session.cookie
    cookie = session_cookie:new{
        name = config.name,
        path = config.path,
        domain = config.domain,
        secure = config.secure
    }
    self._session_cookie = cookie
    return cookie
end

function _M.session_store(self)
    local store
    local store_type = self.config.session.store.store_type
    if store_type == 'shdict' then
        store = shdict_store:new(self.config.session.store)
    elseif store_type == 'redis' then
        store = redis_store:new(self.config.session.store)
    else
        ngx.log(ngx.EMERG, 'invalid session store_type: ', store_type)
    end
    return store
end

return _M
