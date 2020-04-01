nginx-lua-saml-service-provider
===============================

A simple SAML service provider library for [openresty/lua-nginx-module: Embed the Power of Lua into NGINX HTTP servers](https://github.com/openresty/lua-nginx-module).

The reason I create this is I want something an easy to setup and configure for the SAML ID provider at my office.

This project is NOT meant to support all of SAML specs. Actually I haven't even read the SAML spec yet.

If you want a full-fledged SAML service provider, go for [nginx-shib/nginx-http-shibboleth: Shibboleth auth request module for nginx](https://github.com/nginx-shib/nginx-http-shibboleth) and Shibboleth Service Provider at [Products – Shibboleth Consortium](https://www.shibboleth.net/products/).

## Dependencies

* [openresty/lua-resty-string: String utilities and common hash functions for ngx_lua and LuaJIT](https://github.com/openresty/lua-resty-string)
* [openresty/lua-resty-lrucache: Lua-land LRU Cache based on LuaJIT FFI](https://github.com/openresty/lua-resty-lrucache)
* [hamishforbes/lua-ffi-zlib](https://github.com/hamishforbes/lua-ffi-zlib)
* [Phrogz/SLAXML: SAX-like streaming XML parser for Lua](https://github.com/Phrogz/SLAXML)
* [hnakamur/nginx-lua-session](https://github.com/hnakamur/nginx-lua-session)
* `libxmlsec` with OpenSSL support in [XML Security Library](https://www.aleksey.com/xmlsec/)

On Ubuntu, you can install `libxmlsec1` and `libxmlsec1-openssl` with the following command.

```
sudo apt-get install libxmlsec1 libxmlsec1-openssl
```

Then, you need to create symbolic links for shared libraries like:

```
ln -s $(readlink /lib/x86_64-linux-gnu/libz.so.1) /lib/x86_64-linux-gnu/libz.so
ln -s $(readlink /usr/lib/x86_64-linux-gnu/libxml2.so.2) /usr/lib/x86_64-linux-gnu/libxml2.so
ln -s $(readlink /usr/lib/x86_64-linux-gnu/libxmlsec1.so.1) /usr/lib/x86_64-linux-gnu/libxmlsec1.so
ln -s $(readlink /usr/lib/x86_64-linux-gnu/libxmlsec1-openssl.so.1) /usr/lib/x86_64-linux-gnu/libxmlsec1-openssl.so
```

## Test

Install docker-compose and run the following script.

```
./test_files/test.sh
```
