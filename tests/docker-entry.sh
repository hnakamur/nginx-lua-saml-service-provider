#!/bin/bash
set -e

echo '127.0.0.1 sp.example.com idp.example.com' >> /etc/hosts

# run tests with shdict store

rsync -avz /usr/local/ngx-lua-saml-sp-test/shdict_store/etc/nginx/ /etc/nginx/

nginx -g 'daemon off;' &
nginx_pid=$!

while ! timeout 1 bash -c "echo > /dev/tcp/localhost/443" 2> /dev/null; do   
  sleep 1
done
export LUA_PATH='/usr/local/luajit-http-client/lib/?.lua;/usr/local/luajit-http-client/vendor/?.lua;/usr/local/lbase64/?.lua;;'
luajit test.lua

kill $nginx_pid

sleep 1

# run tests with jwt store

rsync -avz /usr/local/ngx-lua-saml-sp-test/jwt_store/etc/nginx/ /etc/nginx/

nginx -g 'daemon off;' &
nginx_pid=$!

while ! timeout 1 bash -c "echo > /dev/tcp/localhost/443" 2> /dev/null; do   
  sleep 1
done
export LUA_PATH='/usr/local/luajit-http-client/lib/?.lua;/usr/local/luajit-http-client/vendor/?.lua;'
luajit test.lua

kill $nginx_pid
#wait $nginx_pid
