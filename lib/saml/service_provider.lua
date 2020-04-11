-- Copyright (C) by Hiroaki Nakamura (hnakamur)

local session_cookie = require "session.cookie"
local saml_sp_request = require "saml.service_provider.request"
local saml_sp_response = require "saml.service_provider.response"
local random = require "saml.service_provider.random"
local time = require "saml.service_provider.time"
local jwt_store = require "saml.service_provider.jwt_store"
local shdict_store = require "saml.service_provider.shdict_store"
local api_error = require "saml.service_provider.api_error"
local access_token = require "saml.service_provider.access_token"
local cjson = require "cjson.safe"

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
    local ts = self:token_store()

    local allowed
    local token, err = self:_get_and_verify_token()
    if err ~= nil then
        ngx.log(ngx.ERR, err)
    else
        local nonce = token.payload.nonce
        local nonce_cfg = self.config.session.store.jwt_nonce
        local first_use
        allowed, first_use, err = ts:use_nonce(nonce, nonce_cfg)
        if err ~= nil then
            ngx.log(ngx.ERR, err)
        end
        if first_use then
            local session_expire_timestamp = token.payload.exp
            local session_expire_seconds_func = function()
                return session_expire_timestamp - ngx.now()
            end
            local new_nonce, err = ts:issue_id(nonce_cfg.usable_count,
                session_expire_seconds_func, nonce_cfg)
            if err ~= nil then
                ngx.log(ngx.ERR, err)
            end
            ngx.header['new-nonce'] = new_nonce
            token.payload.nonce = new_nonce

            local sign_cfg = self.config.session.store.jwt_sign
            local signed_token = token:sign(sign_cfg)
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
        local request_id, err = ts:issue_id(uri_before_login, expire_seconds_func, cfg)
        if err ~= nil then
            return api_error.new{
                err_code = 'err_issue_request_id',
                log_detail = string.format('access, err=%s', err)
            }
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
end

function _M.finish_login(self)
    local sp_resp = self:response()

    local response_xml, err = sp_resp:read_and_base64decode_response()
    if err ~= nil then
        return api_error.new{
            status_code = ngx.HTTP_FORBIDDEN,
            err_code = 'err_decode_saml_response',
            log_detail = string.format('finish_login, err=%s', err)
        }
    end

    local ok, err = sp_resp:verify_response_memory(response_xml)
    if err ~= nil then
        return api_error.new{
            status_code = ngx.HTTP_FORBIDDEN,
            err_code = 'err_verify_resp_mem',
            log_detail = string.format('finish_login, err=%s', err)
        }
    end
    if not ok then
        return api_error.new{
            status_code = ngx.HTTP_FORBIDDEN,
            err_code = 'err_verify_failed',
            log_detail = 'finish_login'
        }
    end

    local vals = sp_resp:take_values_from_response(response_xml)

    local req_expire_timestamp, err = time.parse_iso8601_utc_time(vals.not_on_or_after)
    if err ~= nil then
        -- Malicious date value attack.
        return api_error.new{
            status_code = ngx.HTTP_FORBIDDEN,
            err_code = 'err_invalid_not_on_or_after',
            log_detail = string.format('finish_login, err=%s', err)
        }
    end
    local req_exptime = req_expire_timestamp - ngx.now()

    local ts = self:token_store()
    local redirect_uri, ok, err = ts:take_uri_before_login(vals.request_id, req_exptime)
    ngx.log(ngx.WARN, 'after take_uri_before_login, redirect_uri=', redirect_uri, ', ok=', ok, ', err=', err)
    if err ~= nil or not ok then
        return api_error.new{
            status_code = ngx.HTTP_FORBIDDEN,
            err_code = 'err_take_uri_before_login',
            log_detail = string.format('finish_login, err=%s', err)
        }
    end

    local key_attr_name = self.config.key_attribute_name
    local key_attr = vals.attrs[key_attr_name]
    if key_attr == nil then
        return api_error.new{
            status_code = ngx.HTTP_FORBIDDEN,
            err_code = 'err_attr_not_found',
            log_detail = 'finish_login'
        }
    end

    local session_expire_timestamp, err = time.parse_iso8601_utc_time(vals.session_not_on_or_after)
    if err ~= nil then
        -- Malicious date value attack.
        return api_error.new{
            status_code = ngx.HTTP_FORBIDDEN,
            err_code = 'err_session_exp_time',
            log_detail = string.format('finish_login, err=%s', err)
        }
    end
    local session_expire_seconds_func = function()
        return session_expire_timestamp - ngx.now()
    end

    local jwt_id, err = ts:issue_id('', session_expire_seconds_func,
        self.config.session.store.jwt_id)
    if err ~= nil then
        return api_error.new{
            err_code = 'err_issue_jwt_id',
            log_detail = string.format('finish_login, err=%s', err)
        }
    end
    -- ngx.header.jwt_id = jwt_id

    local nonce_cfg = self.config.session.store.jwt_nonce
    local nonce, err = ts:issue_id(nonce_cfg.usable_count, session_expire_seconds_func,
        nonce_cfg)
    if err ~= nil then
        return api_error.new{
            err_code = 'err_issue_jwt_nonce',
            log_detail = string.format('finish_login, err=%s', err)
        }
    end
    -- ngx.header.jwt_nonce = nonce

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
        return api_error.new{
            status_code = ngx.HTTP_FORBIDDEN,
            err_code = 'err_session_cookie_set_jwt',
            log_detail = string.format('finish_login, err=%s', err)
        }
    end

    return ngx.redirect(redirect_uri)
end

function _M.logout(self)
    local sc = self:session_cookie()
    local ts = self:token_store()

    local token, err = self:_get_and_verify_token()
    if err ~= nil then
        ngx.log(ngx.ERR, 'logout: get and verify token: ', err)
    else
        -- In ideal, we would delete the cookie by setting expiration to the Unix epoch date.
        -- In reality, curl still sends the cookie after receiving the Unix epoch date
        -- with set-cookie, so we have to change the cookie value instead of deleting it.
        local ok, err = sc:set("")
        if err ~= nil then
            ngx.log(ngx.ERR, 'logout: set cookie to empty: ', err)
        end

        local jwt_id = token.payload.jti
        err = ts:delete_id(jwt_id)
        if err ~= nil then
            ngx.log(ngx.ERR, 'logout: delete jwt_id: ', err)
        end

        local nonce = token.payload.nonce
        err = ts:delete_id(nonce)
        if err ~= nil then
            ngx.log(ngx.ERR, 'logout: delete nonce: ', err)
        end
    end
    return ngx.redirect(self.config.redirect.url_after_logout)
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
        secure = config.secure
    }
    self._session_cookie = cookie
    return cookie
end

function _M.token_store(self)
    local store = self._token_store
    if store ~= nil then
        return store
    end

    local store_type = self:token_store_type()
    if store_type == "jwt" then
        local jwt_config = self.config.session.store.jwt
        store = jwt_store:new{
            key_attr_name = self.config.key_attribute_name,
            symmetric_key = jwt_config.symmetric_key,
            algorithm = jwt_config.algorithm
        }
    else
        store = shdict_store:new(self.config.session.store)
    end
    self._token_store = store
    return store
end

function _M.token_store_type(self)
    if self.config.session.store.jwt ~= nil then
        return "jwt"
    end
    return "shared_dict"
end

return _M
