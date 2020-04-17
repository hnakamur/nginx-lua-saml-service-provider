#!/bin/bash

# unit test

export LUA_PATH='/usr/local/luajit-http-client/lib/?.lua;/usr/local/luajit-http-client/vendor/?.lua;/usr/local/lbase64/?.lua;/usr/lib/nginx/lua/?.lua;;'
luajit unit_test.lua --verbose
ret=$?
if [ $ret -ne 0 ]; then
    echo "unit test failed: $ret"
    exit $ret
fi
echo 'unit test OK!'

echo '127.0.0.1 sp.example.com idp.example.com' >> /etc/hosts

# run tests with cookie without domain

rsync -avz /usr/local/ngx-lua-saml-sp-test/cookie_without_domain/etc/nginx/ /etc/nginx/

nginx -g 'daemon off;' &
nginx_pid=$!

while ! timeout 1 bash -c "echo > /dev/tcp/localhost/443" 2> /dev/null; do
  sleep 1
done
export LUA_PATH='/usr/local/luajit-http-client/lib/?.lua;/usr/local/luajit-http-client/vendor/?.lua;/usr/local/lbase64/?.lua;./vendor/?.lua;/etc/nginx/lua/?.lua;;'
luajit test.lua --verbose "$@"
if [ $? -eq 0 ]; then
    echo 'cookie without domain test OK!'
    kill $nginx_pid
    #wait $nginx_pid
else
    tail -n 20 /var/log/nginx/error.log
    cat <<EOF

cookie without domain test failed!!!
You can check log files by running docker exec -it \$container_id bash on another terminal,
or press Ctrl-C to stop this container.
EOF
    wait $nginx_pid
fi

sleep 1

# run tests with cookie with domain

rsync -avz /usr/local/ngx-lua-saml-sp-test/cookie_with_domain/etc/nginx/ /etc/nginx/

nginx -g 'daemon off;' &
nginx_pid=$!

while ! timeout 1 bash -c "echo > /dev/tcp/localhost/443" 2> /dev/null; do
  sleep 1
done
export LUA_PATH='/usr/local/luajit-http-client/lib/?.lua;/usr/local/luajit-http-client/vendor/?.lua;/usr/local/lbase64/?.lua;./vendor/?.lua;/etc/nginx/lua/?.lua;;'
luajit test.lua --verbose "$@"
if [ $? -eq 0 ]; then
    echo 'cookie with domain test OK!'
    kill $nginx_pid
    #wait $nginx_pid
else
    tail -n 20 /var/log/nginx/error.log
    cat <<EOF

cookie with domain test failed!!!
You can check log files by running docker exec -it \$container_id bash on another terminal,
or press Ctrl-C to stop this container.
EOF
    wait $nginx_pid
fi
