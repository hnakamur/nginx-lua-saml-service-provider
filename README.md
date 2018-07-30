lua-resty-saml-service-provider
===============================

A simple SAML service provider library for [openresty/lua-nginx-module: Embed the Power of Lua into NGINX HTTP servers](https://github.com/openresty/lua-nginx-module).

The reason I create this is I want something an easy to setup and configure for the SAML ID provider at my office.

This project is NOT meant to support all of SAML specs.
If you want a full-fledged SAML service provider, go for [nginx-shib/nginx-http-shibboleth: Shibboleth auth request module for nginx](https://github.com/nginx-shib/nginx-http-shibboleth) and Shibboleth Service Provider at [Products – Shibboleth Consortium](https://www.shibboleth.net/products/)

## Dependencies

* [openresty/lua-resty-string: String utilities and common hash functions for ngx_lua and LuaJIT](https://github.com/openresty/lua-resty-string)
* [hamishforbes/lua-ffi-zlib](https://github.com/hamishforbes/lua-ffi-zlib)
* [Phrogz/SLAXML: SAX-like streaming XML parser for Lua](https://github.com/Phrogz/SLAXML)
* [hnakamur/lua-resty-session](https://github.com/hnakamur/lua-resty-session)
