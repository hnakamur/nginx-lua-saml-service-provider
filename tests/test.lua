#!/usr/bin/env luajit

local lu = require('luaunit')
local http_client = require('http.client')
local strings = require('http.client.strings')
local net_url = require('net.url')
local json = require('dkjson')
local sp_config = require('saml.service_provider.config')

local function new_http_client()
    local c = http_client.new()
    c:set_request_default_opts{
        ssl_verifypeer = false,
        ssl_verifyhost = false,
    }
    return c
end

function get_domain_from_set_cookie_val(set_cookie_val)
    local i = string.find(set_cookie_val, '=', 1, true)
    local cookie_val = string.sub(set_cookie_val, i + 1)
    for pair in string.gmatch(cookie_val, '([^;]+);%s*') do
        if strings.has_prefix(pair, 'Domain=') then
            return string.sub(pair, #'Domain=' + 1)
        end
    end
    return nil
end

TestAccessToken = {}
function TestAccessToken:testSignVerify()
    local c = new_http_client()
    local resp, err, errcode

    local token_obj = {
        payload = {
            iss = "https://sp.example.com",
            aud = "https://sp.example.com",
            sub = "john-doe",
            mail = "john.doe@example.com",
            exp = 1586347800,
            nbf = 1586347500,
            jti = "XXXXXXXXXXXXXXXXXXXXXXXXXXX",
            nonce = "YYYYYYYYYYYYYYYYYYY"
        }
    }
    local req = c:new_request{
        method = 'POST',
        url = 'https://sp.example.com/test/sign-jwt',
        body = json.encode(token_obj)
    }
    resp, err, errcode = c:send_request(req)
    lu.assertIsNil(err, 'response#1 err')
    lu.assertEquals(resp.status_code, 200, 'response#1 status_code')
    local signed_token = resp.body

    req = c:new_request{
        method = 'POST',
        url = 'https://sp.example.com/test/verify-jwt',
        body = signed_token
    }
    resp, err, errcode = c:send_request(req)
    lu.assertIsNil(err, 'response#2 err')
    lu.assertEquals(resp.status_code, 200, 'response#2 status_code')

    req = c:new_request{
        method = 'POST',
        url = 'https://sp.example.com/test/verify-jwt',
        body = signed_token
    }
    req.header:add('Disable-All-Keys', '1')
    resp, err, errcode = c:send_request(req)
    lu.assertIsNil(err, 'response#2 err')
    lu.assertEquals(resp.status_code, 403, 'response#2 status_code')

    c:free()
end

TestServiceProvider = {}
function TestServiceProvider:testLoginSuccess()
    local c = new_http_client()
    -- Send first request and receive redirect
    local req = c:new_request{ url = 'https://sp.example.com/' }
    local resp, err, errcode = c:send_request(req)
    lu.assertIsNil(err, 'response#1 err')
    lu.assertEquals(resp.status_code, 302, 'response#1 status_code')
    lu.assertEquals(resp.status_line, 'HTTP/1.1 302 Moved Temporarily', 'response#1 status_line')
    local redirect_url = resp:redirect_url()
    lu.assertIsTrue(strings.has_prefix(redirect_url, 'https://idp.example.com/mock-idp'),
        'response#1 redirect_url prefix')
    local u = net_url.parse(redirect_url)
    lu.assertIsString(u.query['SAMLRequest'], 'response#1 redirect_url query has SAMLRequest parameter')

    -- Follow redirect
    req = c:new_request{ url = redirect_url }
    resp, err, errcode = c:send_request(req)
    lu.assertIsNil(err, 'response#2 err')
    lu.assertEquals(resp.status_code, 200, 'response#2 status_code')
    lu.assertEquals(resp.status_line, 'HTTP/1.1 200 OK', 'response#2 status_line')
    lu.assertIsNil(resp:redirect_url(), 'response#2 redirect_url')

    -- Finish login
    local url = resp.header:get('X-Destination')
    local body = resp.body
    req = c:new_request{
        method = 'POST',
        url = url,
        body = body,
    }
    resp, err, errcode = c:send_request(req)
    lu.assertIsNil(err, 'response#3 err')
    lu.assertEquals(resp.status_code, 302, 'response#3 status_code')
    redirect_url = resp:redirect_url()
    lu.assertNotNil(redirect_url, 'response#3 redirect_url')
    local token = resp.header:get('set-cookie')
    lu.assertNotNil(token, 'response#3 token')
    local cookie_domain = get_domain_from_set_cookie_val(token)
    local cookie_config = sp_config.session.cookie
    local config_cookie_domain = cookie_config.domain
	lu.assertEquals(cookie_domain, config_cookie_domain, 'response#3 cookie set-domain')

    -- Access the site
    req = c:new_request{ url = redirect_url }
    resp, err, errcode = c:send_request(req)
    lu.assertIsNil(err, 'response#4 err')
    lu.assertEquals(resp.status_code, 200, 'response#4 status_code')
    lu.assertEquals(resp.body, 'Welcome to /, mail=john.doe@example.com\n', 'response#4 body')

    -- Logout
    req = c:new_request{ url = 'https://sp.example.com/sso/logout' }
    resp, err, errcode = c:send_request(req)
    lu.assertIsNil(err, 'response#5 err')
    lu.assertEquals(resp.status_code, 302, 'response#5 status_code')
    redirect_url = resp:redirect_url()
    lu.assertEquals(redirect_url, 'https://sp.example.com/sso/logout-finished', 'response#5 redirect_url')

    -- Logouted
    req = c:new_request{ url = redirect_url }
    resp, err, errcode = c:send_request(req)
    lu.assertIsNil(err, 'response#6 err')
    lu.assertEquals(resp.status_code, 200, 'response#6 status_code')

    -- Try to access the site again and redirected to IdP
    req = c:new_request{ url = 'https://sp.example.com/' }
    resp, err, errcode = c:send_request(req)
    lu.assertIsNil(err, 'response#7 err')
    lu.assertEquals(resp.status_code, 302, 'response#7 status_code')
    lu.assertEquals(resp.status_line, 'HTTP/1.1 302 Moved Temporarily', 'response#7 status_line')
    local redirect_url = resp:redirect_url()
    lu.assertIsTrue(strings.has_prefix(redirect_url, 'https://idp.example.com/mock-idp'),
        'response#7 redirect_url prefix')
    local u = net_url.parse(redirect_url)
    lu.assertIsString(u.query['SAMLRequest'], 'response#7 redirect_url query has SAMLRequest parameter')

    c:free()
end

function TestServiceProvider:testFinishLoginReplayAttackProtection()
    local c = new_http_client()
    local c2 = new_http_client()

    -- Send first request and receive redirect
    local req = c:new_request{ url = 'https://sp.example.com/' }
    local resp, err, errcode = c:send_request(req)
    lu.assertIsNil(err, 'response#1 err')
    lu.assertEquals(resp.status_code, 302, 'response#1 status_code')
    local redirect_url = resp:redirect_url()

    -- Follow redirect
    req = c:new_request{ url = redirect_url }
    resp, err, errcode = c:send_request(req)
    lu.assertIsNil(err, 'response#2 err')
    lu.assertEquals(resp.status_code, 200, 'response#2 status_code')
    lu.assertIsNil(resp:redirect_url(), 'response#2 redirect_url')

    -- Finish login
    local url = resp.header:get('X-Destination')
    local body = resp.body
    req = c:new_request{
        method = 'POST',
        url = url,
        body = body,
    }
    resp, err, errcode = c:send_request(req)
    lu.assertIsNil(err, 'response#3 err')
    lu.assertEquals(resp.status_code, 302, 'response#3 status_code')
    redirect_url = resp:redirect_url()
    lu.assertNotNil(redirect_url, 'response#3 redirect_url')

    -- Replay attack by another client
    req = c:new_request{
        method = 'POST',
        url = url,
        body = body,
    }
    resp, err, errcode = c2:send_request(req)
    lu.assertIsNil(err, 'attacker response err')
    lu.assertEquals(resp.status_code, 403, 'attacker response status_code')
    redirect_url = resp:redirect_url()
    lu.assertIsNil(redirect_url, 'attacker response redirect_url')

    c2:free()
    c:free()
end


function TestServiceProvider:testURLAfterLoginSuccess()
    local c = new_http_client()

    -- Send first request and receive redirect
    local first_url_path = '/foo'
    local first_url = 'https://sp.example.com' .. first_url_path
    local req = c:new_request{ url = first_url }
    local resp, err, errcode = c:send_request(req)
    lu.assertIsNil(err, 'response#1 err')
    lu.assertEquals(resp.status_code, 302, 'response#1 status_code')
    local redirect_url = resp:redirect_url()
    lu.assertIsTrue(strings.has_prefix(redirect_url, 'https://idp.example.com/mock-idp'),
        'response#1 redirect_url prefix')

    -- Follow redirect
    req = c:new_request{ url = redirect_url }
    resp, err, errcode = c:send_request(req)
    lu.assertIsNil(err, 'response#2 err')
    lu.assertEquals(resp.status_code, 200, 'response#2 status_code')

    -- Finish login
    local url = resp.header:get('X-Destination')
    local body = resp.body
    req = c:new_request{
        method = 'POST',
        url = url,
        body = body,
    }
    resp, err, errcode = c:send_request(req)
    lu.assertIsNil(err, 'response#3 err')
    redirect_url = resp:redirect_url()
    lu.assertEquals(redirect_url, first_url, 'response#3 redirect_url')

    -- Access the site
    req = c:new_request{ url = redirect_url }
    resp, err, errcode = c:send_request(req)
    lu.assertIsNil(err, 'response#4 err')
    lu.assertEquals(resp.body,
        string.format('Welcome to %s, mail=john.doe@example.com\n', first_url_path),
        'response#4 body')

    c:free()
end

function TestServiceProvider:testFinishLoginBadBody()
    local c = new_http_client()

    local cases = {
        { body = '' },
        { body = 'SAMLResponse=' },
        { body = 'SAMLResponse=foo' },
    }
    for i, tc in ipairs(cases) do
        local req = c:new_request{
            method = 'POST',
            url = 'https://sp.example.com/sso/finish-login',
            body = tc.body
        }
        local resp, err, errcode = c:send_request(req)
        lu.assertIsNil(err, string.format('case %d: err', i))
        lu.assertEquals(resp.status_code, 403, string.format('case %d: status_code', i))
    end

    c:free()
end



os.exit(lu.LuaUnit.run())
