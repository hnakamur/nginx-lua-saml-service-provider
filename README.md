lua-resty-saml-service-provider
===============================

A simple SAML service provider library for [openresty/lua-nginx-module: Embed the Power of Lua into NGINX HTTP servers](https://github.com/openresty/lua-nginx-module).

The reason I create this is I want something an easy to setup and configure for the SAML ID provider at my office.

This project is NOT meant to support all of SAML specs. Actually I haven't even read the SAML spec yet.

If you want a full-fledged SAML service provider, go for [nginx-shib/nginx-http-shibboleth: Shibboleth auth request module for nginx](https://github.com/nginx-shib/nginx-http-shibboleth) and Shibboleth Service Provider at [Products – Shibboleth Consortium](https://www.shibboleth.net/products/).

## Dependencies

* [openresty/lua-resty-string: String utilities and common hash functions for ngx_lua and LuaJIT](https://github.com/openresty/lua-resty-string)
* [hamishforbes/lua-ffi-zlib](https://github.com/hamishforbes/lua-ffi-zlib)
* [Phrogz/SLAXML: SAX-like streaming XML parser for Lua](https://github.com/Phrogz/SLAXML)
* [hnakamur/lua-resty-session](https://github.com/hnakamur/lua-resty-session)
* `xmlsec1` command with OpenSSL support in [XML Security Library](https://www.aleksey.com/xmlsec/)

On CentOS7, you can install `xmlsec1` command with OpenSSL support with the following command:

```
sudo yum install xmlsec1 xmlsec1-openssl
```


## Caveats

Generally speaking you should avoid blocking I/O in programs with [openresty/lua-nginx-module](https://github.com/openresty/lua-nginx-module).
However, this library contains blocking I/O when a user finished logging in:

* Save a SAML response to a temporary file using Lua's `os.tmpname`, `io.open`, and `io.write`.
* Run the command `xmlsec` with Lua's `os.execute`.

For the latter, I found [jprjr/lua-resty-exec: Run external programs in OpenResty without spawning a shell or blocking](https://github.com/jprjr/lua-resty-exec), but I haven't tried it yet. With this, you need to manage a socket file. But I like to avoid it this time for a simpler setup.

For the best performance, I would rather call functions in [XML Security Library](https://www.aleksey.com/xmlsec/) using LuaJIT FFI.

In `apps/xmlsec.c`, the function `xmlSecAppVerifyFile` calls `xmlSecAppXmlDataCreate`, then `xmlSecParseFile`. If you use `xmlSecParseMemoryExt` instead, you don't need to save the SAML response to a temporary file. However a lot of efforts for this implementation, and I choose not to do this now.

Reading the ID provider's certificate will still remain as a blocking I/O with the above FFI calls.
I just skimmed at xmlsec source code, so this could be wrong.

However, for my use case now, the site traffic is very low, and verifying the SAML response is only needed when users finish logging in, so I don't think it is a problem using blocking I/O for saving a temporary file and running a command synchronously.
