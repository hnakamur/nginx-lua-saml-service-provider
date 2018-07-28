-- Copyright (C) by Hiroaki Nakamura (hnakamur)

local session_cookie = require "session.cookie"
local session_store = require "session.store"
local saml_sp_request = require "saml.service_provider.request"
local saml_sp_response = require "saml.service_provider.response"

local resty_random = require "resty.random"
local str = require "resty.string"
local setmetatable = setmetatable

local _M = { _VERSION = '0.1.0' }

local mt = { __index = _M }

function _M.new(self, config)
    return setmetatable({
        config = config
    }, mt)
end

function _M.access(self)
    local session_cookie = self:session_cookie()
    local session_id, err = session_cookie:get()
    if err ~= nil then
        return false,
            string.format("failed to get session cookie during access, err=%s", err)
    end

    local key_attr = nil
    if session_id ~= nil then
        local ss = self:session_store()
        key_attr = ss:get(session_id)
        if key_attr ~= nil and ss.expire_seconds ~= 0 then
            local ok, err = ss:extend(session_id)
            if err ~= nil then
                return false,
                    string.format("failed to extend session during access, err=%s", err)
            end
        end
    end

    if session_id == nil or key_attr == nil then
        local sp_req = self:request()
        return sp_req:redirect_to_idp_to_login()
    end

    local key_attr_name = self.config.key_attribute_name
    ngx.req.set_header(key_attr_name, key_attr)
    return true
end

function _M.finish_login(self)
    local sp_resp = self:response()

    local response_xml, err = sp_resp:read_and_base64decode_response()
    if err ~= nil then
        return false,
            string.format("failed to read and decode response during finish_login, err=%s", err)
    end

    local ok, err = sp_resp:verify_response(response_xml)
    if err ~= nil then
        return false,
            string.format("failed to verify response during finish_login, err=%s", err)
    end

    local attrs, err = sp_resp:take_attributes_from_response(response_xml)
    if err ~= nil then
        return false,
            string.format("failed to take attributes from response during finish_login, err=%s", err)
    end

    local key_attr_name = self.config.key_attribute_name
    local key_attr = attrs[key_attr_name]
    if key_attr == nil then
        return false,
            string.format('failed to get key attribute "%s" from response during finish_login, err=%s', key_attr_name, err)
    end

    local ss = self:session_store()
    local session_id, err = ss:add(key_attr)
    if err ~= nil then
        return false,
            string.format("failed to create session dict entry during finish_login, err=%s", err)
    end

    local sc = self:session_cookie()
    local ok, err = sc:set(session_id)
    if err ~= nil then
        return false,
            string.format("failed to set session cookie during finish_login, err=%s", err)
    end

    local dict_name = self.config.request.urls_before_login.dict_name
    local redirect_urls_dict = dict_name ~= nil and ngx.shared[dict_name] or nil
    ngx.log(ngx.ERR, string.format("finish_login dict_name=%s, dict=%s", dict_name, redirect_urls_dict))
    if redirect_urls_dict ~= nil then
        local request_id, err = sp_resp:take_request_id_from_response(response_xml)
        if err ~= nil then
            return false,
                string.format("failed to take request ID from response during finish_login, err=%s", err)
        end
        ngx.log(ngx.ERR, string.format("finish_login request_id=%s", request_id))

        local redirect_url = redirect_urls_dict:get(request_id)
        ngx.log(ngx.ERR, string.format("finish_login redirect_url=%s", redirect_url))
        if redirect_url ~= nil then
            redirect_urls_dict:delete(request_id)
            return ngx.redirect(redirect_url)
        end
    end
    return ngx.redirect(self.config.redirect.url_after_login)
end

function _M.logout(self)
    local sc = self:session_cookie()
    local session_id, err = sc:get()
    if err ~= nil then
        return false,
            string.format("failed to get session cookie during logout, err=%s", err)
    end

    if session_id ~= nil then
        local ss = self:session_store()
        ss:delete(session_id)
    end

    local ok, err = sc:delete()
    if err ~= nil then
        return false,
            string.format("failed to delete session cookie during logout, err=%s", err)
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
        urls_before_login = config.urls_before_login,
        request_id_generator = function()
            return "_" .. str.to_hex(resty_random.bytes(config.request_id_byte_length))
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

    local config = self.config.response
    response = saml_sp_response:new{
        xmlsec_command = config.xmlsec_command,
        idp_cert_filename = config.idp_cert_filename,
        key_attribute_name = config.key_attribute_name
    }
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

function _M.session_store(self)
    local store = self._session_store
    if store ~= nil then
        return store
    end

    local config = self.config.session.store
    store = session_store:new{
        dict_name = config.dict_name,
        id_generator = function()
            return str.to_hex(resty_random.bytes(config.id_byte_length))
        end
    }
    self._session_store = store
    return store
end

return _M
