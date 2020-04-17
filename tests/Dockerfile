FROM ubuntu:18.04

RUN apt-get update \
 && apt-get install -y software-properties-common \
 && add-apt-repository -y ppa:hnakamur/openresty-luajit \
 && add-apt-repository -y ppa:hnakamur/libsxg \
 && add-apt-repository -y ppa:hnakamur/nginx \
 && apt-get update \
 && apt-get install -y luajit libluajit-5.1 libluajit-5.1-common nginx

# lua-cjson needed by github.com/cdbattags/lua-resty-jwt
RUN apt-get install -y libxmlsec1 libxmlsec1-openssl lua-cjson \
 && ln -s $(readlink /lib/x86_64-linux-gnu/libz.so.1) /lib/x86_64-linux-gnu/libz.so \
 && ln -s $(readlink /usr/lib/x86_64-linux-gnu/libxml2.so.2) /usr/lib/x86_64-linux-gnu/libxml2.so \
 && ln -s $(readlink /usr/lib/x86_64-linux-gnu/libxmlsec1.so.1) /usr/lib/x86_64-linux-gnu/libxmlsec1.so \
 && ln -s $(readlink /usr/lib/x86_64-linux-gnu/libxmlsec1-openssl.so.1) /usr/lib/x86_64-linux-gnu/libxmlsec1-openssl.so

RUN mkdir /etc/nginx/saml

RUN openssl req -new -newkey rsa:2048 -sha1 -x509 -nodes \
    -set_serial 1 \
    -days 365 \
    -subj "/C=JP/ST=Osaka/L=Osaka City/CN=sp.example.com" \
    -out /etc/nginx/saml/sp.example.com.crt \
    -keyout /etc/nginx/saml/sp.example.com.key

RUN openssl req -new -newkey rsa:2048 -sha1 -x509 -nodes \
    -set_serial 1 \
    -days 365 \
    -subj "/C=JP/ST=Osaka/L=Osaka City/CN=idp.example.com" \
    -out /etc/nginx/saml/idp.example.com.crt \
    -keyout /etc/nginx/saml/idp.example.com.key

RUN apt-get update \
 && apt-get install -y libcurl4 git \
 && ln -s libcurl.so.4 /usr/lib/x86_64-linux-gnu/libcurl.so \
 && cd /usr/local \
 && git clone https://github.com/hnakamur/luajit-http-client

RUN apt-get install -y rsync curl

RUN cd /tmp \
 && git clone https://github.com/hnakamur/nginx-lua-session \
 && cd nginx-lua-session \
 && git checkout support_all_params  \
 && cp -pr lib/* /usr/lib/nginx/lua/

COPY tests/ /usr/local/ngx-lua-saml-sp-test/
COPY lib/ /usr/lib/nginx/lua/

WORKDIR /usr/local/ngx-lua-saml-sp-test/
ENTRYPOINT ["./docker-entry.sh"]
