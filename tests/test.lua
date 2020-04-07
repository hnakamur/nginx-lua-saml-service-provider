#!/usr/bin/env luajit

local lu = require('luaunit')
local strings = require('http.client.strings')
local net_url = require('net.url')

TestServiceProvider = {}
function TestServiceProvider:testLoginSuccess()
    local http_client = require('http.client')

    local c = http_client.new()
    c:set_request_default_opts{
        ssl_verifypeer = false,
        ssl_verifyhost = false,
    }

    local resp, err, errcode
    -- Send first request and receive redirect
    resp, err, errcode = c:send_request(
        c:new_request{ url = 'https://sp.example.com/' }
    )
    lu.assertIsNil(err, 'response#1 err')
    lu.assertEquals(resp.status_code, 302, 'response#1 status_code')
    lu.assertEquals(resp.status_line, 'HTTP/1.1 302 Moved Temporarily', 'response#1 status_line')
    local redirect_url = resp:redirect_url()
    lu.assertIsTrue(strings.has_prefix(redirect_url, 'https://idp.example.com/mock-idp'),
        'response#1 redirect_url prefix')
    local u = net_url.parse(redirect_url)
    lu.assertIsString(u.query['SAMLRequest'], 'response#1 redirect_url query has SAMLRequest parameter')

    -- Follow redirect
    resp, err, errcode = c:send_request(
        c:new_request{ url = redirect_url }
    )
    lu.assertIsNil(err, 'response#2 err')
    lu.assertEquals(resp.status_code, 200, 'response#2 status_code')
    lu.assertEquals(resp.status_line, 'HTTP/1.1 200 OK', 'response#2 status_line')
    lu.assertIsNil(resp:redirect_url(), 'response#2 redirect_url')

    -- Finish login
    local url = resp.header:get('X-Destination')
    local body = resp.body
    resp, err, errcode = c:send_request(
        c:new_request{
            method = 'POST',
            url = url,
            body = body,
        }
    )
    lu.assertIsNil(err, 'response#3 err')
    lu.assertEquals(resp.status_code, 302, 'response#3 status_code')
    redirect_url = resp:redirect_url()
    lu.assertNotNil(redirect_url, 'response#3 redirect_url')

    -- Access the site
    local resp
    resp, err, errcode = c:send_request(
        c:new_request{ url = redirect_url }
    )
    lu.assertIsNil(err, 'response#4 err')
    lu.assertEquals(resp.status_code, 200, 'response#4 status_code')
    lu.assertEquals(resp.body, 'Welcome to /, mail=john.doe@example.com\n', 'response#4 body')

    -- Logout
    resp, err, errcode = c:send_request(
        c:new_request{ url = 'https://sp.example.com/sso/logout' }
    )
    lu.assertIsNil(err, 'response#5 err')
    lu.assertEquals(resp.status_code, 302, 'response#5 status_code')
    redirect_url = resp:redirect_url()
    lu.assertEquals(redirect_url, 'https://sp.example.com/sso/logout-finished', 'response#5 redirect_url')

    -- Logouted
    resp, err, errcode = c:send_request(
        c:new_request{ url = redirect_url }
    )
    lu.assertIsNil(err, 'response#6 err')
    lu.assertEquals(resp.status_code, 200, 'response#6 status_code')

    -- Try to access the site again and redirected to IdP
    resp, err, errcode = c:send_request(
        c:new_request{ url = 'https://sp.example.com/' }
    )
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
    local http_client = require('http.client')

    local c = http_client.new()
    c:set_request_default_opts{
        ssl_verifypeer = false,
        ssl_verifyhost = false,
    }

    local c2 = http_client.new()
    c2:set_request_default_opts{
        ssl_verifypeer = false,
        ssl_verifyhost = false,
    }

    local resp, err, errcode
    -- Send first request and receive redirect
    resp, err, errcode = c:send_request(
        c:new_request{ url = 'https://sp.example.com/' }
    )
    lu.assertIsNil(err, 'response#1 err')
    lu.assertEquals(resp.status_code, 302, 'response#1 status_code')
    local redirect_url = resp:redirect_url()

    -- Follow redirect
    resp, err, errcode = c:send_request(
        c:new_request{ url = redirect_url }
    )
    lu.assertIsNil(err, 'response#2 err')
    lu.assertEquals(resp.status_code, 200, 'response#2 status_code')
    lu.assertIsNil(resp:redirect_url(), 'response#2 redirect_url')

    -- Finish login
    local url = resp.header:get('X-Destination')
    local body = resp.body
    resp, err, errcode = c:send_request(
        c:new_request{
            method = 'POST',
            url = url,
            body = body,
        }
    )
    lu.assertIsNil(err, 'response#3 err')
    lu.assertEquals(resp.status_code, 302, 'response#3 status_code')
    redirect_url = resp:redirect_url()
    lu.assertNotNil(redirect_url, 'response#3 redirect_url')

    -- Replay attack by another client
    resp, err, errcode = c2:send_request(
        c:new_request{
            method = 'POST',
            url = url,
            body = body,
        }
    )
    lu.assertIsNil(err, 'attacker response err')
    lu.assertEquals(resp.status_code, 403, 'attacker response status_code')
    redirect_url = resp:redirect_url()
    lu.assertIsNil(redirect_url, 'attacker response redirect_url')

    c2:free()
    c:free()
end


function TestServiceProvider:testURLAfterLoginSuccess()
    local http_client = require('http.client')

    local c = http_client.new()
    c:set_request_default_opts{
        ssl_verifypeer = false,
        ssl_verifyhost = false,
    }

    local resp, err, errcode
    -- Send first request and receive redirect
    local first_url_path = '/foo'
    local first_url = 'https://sp.example.com' .. first_url_path
    resp, err, errcode = c:send_request(
        c:new_request{ url = first_url }
    )
    lu.assertIsNil(err, 'response#1 err')
    lu.assertEquals(resp.status_code, 302, 'response#1 status_code')
    local redirect_url = resp:redirect_url()
    lu.assertIsTrue(strings.has_prefix(redirect_url, 'https://idp.example.com/mock-idp'),
        'response#1 redirect_url prefix')

    -- Follow redirect
    resp, err, errcode = c:send_request(
        c:new_request{ url = redirect_url }
    )
    lu.assertIsNil(err, 'response#2 err')
    lu.assertEquals(resp.status_code, 200, 'response#2 status_code')

    -- Finish login
    local url = resp.header:get('X-Destination')
    local body = resp.body
    resp, err, errcode = c:send_request(
        c:new_request{
            method = 'POST',
            url = url,
            body = body,
        }
    )
    lu.assertIsNil(err, 'response#3 err')
    redirect_url = resp:redirect_url()
    lu.assertEquals(redirect_url, first_url, 'response#3 redirect_url')

    -- Access the site
    local resp
    resp, err, errcode = c:send_request(
        c:new_request{ url = redirect_url }
    )
    lu.assertIsNil(err, 'response#4 err')
    lu.assertEquals(resp.body,
        string.format('Welcome to %s, mail=john.doe@example.com\n', first_url_path),
        'response#4 body')
end

function TestServiceProvider:testFinishLoginBadBody()
    local http_client = require('http.client')

    local c = http_client.new()
    c:set_request_default_opts{
        ssl_verifypeer = false,
        ssl_verifyhost = false,
    }

    local cases = {
        { body = '' },
        { body = 'SAMLResponse=' },
        { body = 'SAMLResponse=foo' },
    }
    for i, tc in ipairs(cases) do
        local resp, err, errcode = c:send_request(
            c:new_request{
                method = 'POST',
                url = 'https://sp.example.com/sso/finish-login',
                body = tc.body
            }
        )
        lu.assertIsNil(err, string.format('case %d: err', i))
        lu.assertEquals(resp.status_code, 403, string.format('case %d: status_code', i))
    end
end

os.exit(lu.LuaUnit.run())
