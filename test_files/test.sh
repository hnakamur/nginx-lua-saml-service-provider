#!/bin/sh
if [ ! -f test_files/idp/etc/nginx/saml/idp.example.com.crt ]; then
    openssl req -new -newkey rsa:2048 -sha1 -x509 -nodes \
        -set_serial 1 \
        -days 365 \
        -subj "/C=JP/ST=Osaka/L=Osaka City/CN=idp.example.com" \
        -out test_files/idp/etc/nginx/saml/idp.example.com.crt \
        -keyout test_files/idp/etc/nginx/saml/idp.example.com.key
fi
docker-compose up --build --abort-on-container-exit
