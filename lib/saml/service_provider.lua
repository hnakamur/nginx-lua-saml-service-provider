-- Copyright (C) by Hiroaki Nakamura (hnakamur)

local session_cookie = require "session.cookie"
local session_store = require "session.store"
local saml_sp_request = require "saml.service_provider.request"
local saml_sp_response = require "saml.service_provider.response"
local random = require "saml.service_provider.random"

local setmetatable = setmetatable

local _M = { _VERSION = '0.9.0' }

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
    end

    if session_id == nil or key_attr == nil then
        local sp_req = self:request()
        return sp_req:redirect_to_idp_to_login()
    end

    local key_attr_name = self.config.key_attribute_name
    ngx.req.set_header(key_attr_name, key_attr)
    return true
end

local function has_prefix(s, prefix)
    return #s >= #prefix and string.sub(s, 1, #prefix) == prefix
end

local function parse_iso8601_utc_time(str)
    local year, month, day, hour, min, sec = str:match('(%d+)-(%d+)-(%d+)T(%d+):(%d+):(%d+)')
    return os.time{year=year, month=month, day=day, hour=hour, min=min, sec=sec}
end

function _M.finish_login(self)
    local sp_resp = self:response()

    local response_xml, redirect_uri, err = sp_resp:read_and_base64decode_response()
    if err ~= nil then
        return false,
            string.format("failed to read and decode response during finish_login: %s", err)
    end

    if self.config.response.idp_certificate ~= nil then
        local err = sp_resp:verify_response_memory(response_xml)
        if err ~= nil then
            return false,
                string.format("failed to verify response on memory during finish_login, err=%s", err)
        end
    else
        local ok, err = sp_resp:verify_response(response_xml)
        if err ~= nil then
            return false,
                string.format("failed to verify response during finish_login, err=%s", err)
        end
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

    local exptime_str = sp_resp:take_session_expiration_time_from_response(response_xml)
    local exptime = parse_iso8601_utc_time(exptime_str)
    local duration = exptime - ngx.time()
    ngx.log(ngx.DEBUG, "exptime=", exptime, ", duration=", duration)

    local ss = self:session_store()
    local session_id, err = ss:add(key_attr, duration)
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

    if not has_prefix(redirect_uri, '/') then
        redirect_uri = '/'
    end
    return ngx.redirect(redirect_uri)
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

function _M.session_store(self)
    local store = self._session_store
    if store ~= nil then
        return store
    end

    local config = self.config.session.store
    store = session_store:new{
        dict_name = config.dict_name,
        id_generator = function()
            return random.hex(config.request_id_byte_length or 16)
        end
    }
    self._session_store = store
    return store
end

return _M
