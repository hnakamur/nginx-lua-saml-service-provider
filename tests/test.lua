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
    lu.assertIsNil(err, 'response#1')
    lu.assertEquals(resp.status_code, 302, 'response#1 status_code')
    lu.assertEquals(resp.status_line, 'HTTP/1.1 302 Moved Temporarily', 'response#1 status_line')
    local redirect_url = resp:redirect_url()
    -- print('response#1 redirect_url=', redirect_url)
    lu.assertIsTrue(strings.has_prefix(redirect_url, 'https://idp.example.com/mock-idp'),
        'response#1 redirect_url prefix')
    local u = net_url.parse(redirect_url)
    lu.assertIsString(u.query['SAMLRequest'], 'response#1 redirect_url query has SAMLRequest parameter')
    lu.assertIsString(u.query['RelayState'], 'response#1 redirect_url query has RelayState parameter')

    -- Follow redirect
    local resp2
    resp2, err, errcode = c:send_request(
        c:new_request{ url = redirect_url }
    )
    lu.assertIsNil(err, 'response#2')
    lu.assertEquals(resp2.status_code, 200, 'response#2 status_code')
    lu.assertEquals(resp2.status_line, 'HTTP/1.1 200 OK', 'response#2 status_line')
    lu.assertIsNil(resp2:redirect_url(), 'response#2 redirect_url')

    -- Finish login
    local url = resp2.header:get('X-Destination')
    -- print('finish_login, url=', url)
    local body = resp2.body
    local resp3
    resp3, err, errcode = c:send_request(
        c:new_request{
            method = 'POST',
            url = url,
            body = body,
        }
    )
    lu.assertIsNil(err, 'response#3')
    lu.assertEquals(resp3.status_code, 302, 'response#3 status_code')
    redirect_url = resp3:redirect_url()
    lu.assertNotNil(redirect_url, 'response#3 redirect_url')
    -- print('response#3 redirect_url=', redirect_url)
    -- for _, line in ipairs(resp3.header) do
    --     print('response#3 header=', line)
    -- end

    local resp4
    resp4, err, errcode = c:send_request(
        c:new_request{ url = redirect_url }
    )
    lu.assertIsNil(err, 'response#4')
    lu.assertEquals(resp4.status_code, 200, 'response#4 status_code')
    -- for _, line in ipairs(resp4.header) do
    --     print('response#4 header=', line)
    -- end
    -- print('resp4.body=', resp4.body)
    lu.assertEquals(resp4.body, 'Welcome to /, mail=john.doe@example.com\n', 'response#4 body')
end

os.exit(lu.LuaUnit.run())
