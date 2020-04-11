local session_store = require "session.store"
local random = require "saml.service_provider.random"

local _M = {}

local mt = { __index = _M }

--- Creates shared dict session store manager.
-- @param config        The config (table).
function _M.new(self, config)
    local dict_name = config.shared_dict_name
    if dict_name == nil then
        ngx.log(ngx.EMEG, 'shared_dict_name must be defined in config')
    end
    local dict = ngx.shared[dict_name]
    if dict == nil then
        ngx.log(ngx.EMEG, string.format('shared dict not defined, dict_name=%s', dict_name))
    end

    return setmetatable({
        dict = dict,
        dict_name = dict_name,
        request_id_expire_seconds = config.request_id_expire_seconds or 300,
        request_id_prefix = config.request_id_prefix or '_',
        request_id_random_byte_len = config.request_id_random_byte_len or 16,
        jti_generator = function()
            return 't' .. random.hex(config.jti_random_byte_len or 16)
        end,
        nonce_generator = function()
            return 'n' .. random.hex(config.nonce_random_byte_len or 16)
        end,
        session_store = session_store:new{
            dict_name = dict_name,
            id_generator = function()
                return random.hex(config.session_id_byte_length or 16)
            end
        }
    }, mt)
end

function _M.issue_id(self, value, expire_seconds, config)
    local dict = self.dict
    for i = 1, config.issue_max_retry_count do
        local id = config.prefix .. random.hex(config.random_byte_len)
        local success, err, forcible = dict:add(id, value, expire_seconds)
        if success then
            return id
        elseif err ~= "exists" then
            return nil, string.format('issue_id: %s', err)
        end
    end
    return nil, 'issue_id: exceeded max_retry_count'
end

function _M.take_uri_before_login(self, request_id, exptime)
    local dict = self.dict
    -- local dict = ngx.shared[self.dict_name]
    local uri_before_login, err = dict:get(request_id)
    if err ~= nil or uri_before_login == '' then
        -- Already finished login, this is replay attack.
        return nil, false, err
    end

    -- NOTE: We MUST keep used request_id until not_on_or_after
    -- because it is needed by the SAML spec.
    --
    -- Document identifier: saml-profiles-2.0-os
    -- Location: http://docs.oasis-open.org/security/saml/v2.0/
    --
    -- 4.1.4.5 POST-Specific Processing Rules
    -- The service provider MUST ensure that bearer assertions are not replayed,
    -- by maintaining the set of used ID values for the length of time for which
    -- the assertion would be considered valid based on the NotOnOrAfter attribute
    -- in the <SubjectConfirmationData>.
    if exptime > 0 then
        local success, err, forcible = dict:replace(request_id, '', exptime)
        if not success then
            return nil, false,
                string.format("empty uri_before_login for request_id, dict=%s, request_id=%s, err=%s, forcible=%s",
                              self.dict_name, request_id, err, forcible)
        end
    else
        dict:delete(request_id)
    end
    return uri_before_login, true, nil
end

-- ログイン成功時の処理
-- shared dictは jti のキーでセッションの有効期限やメールアドレスなどをログイン完了時に設定します。
-- それとは別に jti + ':" + nonce のキーに利用回数の残りと期限を設定します。
-- key: jti
-- value:
-- {
--   "sub": "john-doe",
--   "exp": 1586347800,
--   "mail": "john.doe@example.com",
--   "nonce": "XXXXXXXX"
-- }
-- ttl: sessions'exptime
-- jwt_token
-- {
--   "header": {"typ":"JWT", "alg":"HS256"},
--   "payload": {
--     "kid": "key_2020_001_ZZZZZZZZZZZZZZZ",
--     "iss": "https://sp.example.com",
--     "aud": "https://sp.example.com",
--     "sub": "john-doe",
--     "mail": "john.doe@example.com",
--     "exp": 1586347800,
--     "nbf": 1586347500,
--     "jti": "XXXXXXXXXXXXXXXXXXXXXXXXXXX",
--     "nonce": "YYYYYYYYYYYYYYYYYYY"
--   }
-- }
--
-- key: jti + ':' + nonce
-- value: nonce_usable_count (ex: 3)
-- ttl: session's exptime
--
-- アクセス時の処理
-- jwt を共有鍵で検証。
-- cookieで送られてきた jwt 内の jti で shared dictを引き、 sub, mail, exp がjwt内と一致するかチェック。
-- jwt 内の iss と aud が設定ファイルの値と一致するかチェック。
-- local nonce_key = jti + ':' + nonce
-- local newval, err, forcible = dict:incr(nonce_key, -1)
-- newval < 0 or err ~= nil なら 403 Forbidden
-- if newval == nonce_key_usable_count -1 then -- first use
--   local success, err = dict:expire(nonce_key, nonce_exptime_seconds)
--   -- 新しいnonceを発行
--   local exptime = jwt_token.payload.exp - ngx.time()
--   while exptime > 0 then
--     local new_nonce = issue_new_nonce
--     local new_nonce_key = jti + ':' + new_nonce
--     local success, err, forcieble = dict:add(new_nonce_key, nonce_usable_count, exptime)
--     if success then
--       jwt_token.nonce = new_nonce
--       local jwt_token_str = cjson.encode(jwt_token)
--       success, err, forcible = dict:replace(jti, jwt_token_str, exptime)
--       if err ~= nil or not successible then
--       end
--       set-cookie: jwt_token_str
--       return
--     elseif err ~= 'exists' then
--       log_error
--       return
--     end
--     exptime = jwt_token.payload.exp - ngx.time()
--   end
-- end
--
-- jwt_config
-- algorithm = 'HS256',
-- current_key_id: 'key_2020_001_ZZZZZZZZZZZZZZZZZ',
-- keys = {
--   key_2020_001_ZZZZZZZZZZZZZZZZZ = 'WWWWWWWWWWWWWWWWWWWWWWW',
-- },
-- nonce_usable_count = 1,
-- nonce_exptime_seconds = 3, -- exptime in seconds after first use

function _M.update_on_finish_login(self)
end

function _M.update_on_access(self)
end

--- Store the attribute value and issue session ID.
-- @param attr_val      The attribute value (string).
-- @param exptime       The timestamp for expiration (number).
-- @return the issued session ID (string).
-- @return err (string or nil).
function _M.store(self, attr_val, exptime)
    local duration = exptime - ngx.now()
    local session_id, err = self.session_store:add(attr_val, duration)
    if err ~= nil then
        return "",
            string.format("failed to add attribute to shared dict, err=%s", err)
    end
    return session_id, nil
end

--- Retrieve the attribute value related to session_id
-- @param session_id    The session id (string).
-- @return the attribute value (string or nil).
function _M.retrieve(self, session_id)
    if session_id == nil or session_id == "" then
        return nil
    end
    return self.session_store:get(session_id)
end

--- Delete the attribute related to session_id from the shared dict.
-- @param session_id    The session id (string).
function _M.delete(self, session_id)
    self.session_store:delete(session_id)
end

return _M
