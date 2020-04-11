#!/bin/bash

# unit test
export LUA_PATH='/usr/local/luajit-http-client/lib/?.lua;/usr/local/luajit-http-client/vendor/?.lua;/usr/local/lbase64/?.lua;/usr/lib/nginx/lua/?.lua;;'
luajit unit_test.lua
ret=$?
if [ $ret -ne 0 ]; then
    echo "unit test failed: $ret"
    exit $ret
fi
echo 'unit test OK!'

echo '127.0.0.1 sp.example.com idp.example.com' >> /etc/hosts

# run tests with shdict store

rsync -avz /usr/local/ngx-lua-saml-sp-test/shdict_store/etc/nginx/ /etc/nginx/

nginx -g 'daemon off;' &
nginx_pid=$!

while ! timeout 1 bash -c "echo > /dev/tcp/localhost/443" 2> /dev/null; do
  sleep 1
done
export LUA_PATH='/usr/local/luajit-http-client/lib/?.lua;/usr/local/luajit-http-client/vendor/?.lua;/usr/local/lbase64/?.lua;./vendor/?.lua;;'
luajit test.lua "$@"
if [ $? -eq 0 ]; then
    kill $nginx_pid
else
    tail -n 20 /var/log/nginx/error.log
    cat <<EOF

shdict_store test failed!!!
You can check log files by running docker exec -it \$container_id bash on another terminal,
or press Ctrl-C to stop this container.
EOF
    wait $nginx_pid
fi
#
#sleep 1
#
## run tests with jwt store
#
#rsync -avz /usr/local/ngx-lua-saml-sp-test/jwt_store/etc/nginx/ /etc/nginx/
#
#nginx -g 'daemon off;' &
#nginx_pid=$!
#
#while ! timeout 1 bash -c "echo > /dev/tcp/localhost/443" 2> /dev/null; do
#  sleep 1
#done
#export LUA_PATH='/usr/local/luajit-http-client/lib/?.lua;/usr/local/luajit-http-client/vendor/?.lua;'
#luajit test.lua "$@"
#if [ $? -eq 0 ]; then
#    kill $nginx_pid
#else
#    tail -n 20 /var/log/nginx/error.log
#    cat <<EOF
#
#jwt_store test failed!!!
#You can check log files by running docker exec -it \$container_id bash on another terminal,
#or press Ctrl-C to stop this container.
#EOF
#    wait $nginx_pid
#fi
