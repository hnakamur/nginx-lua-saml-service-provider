FROM ubuntu:18.04

RUN apt-get update \
 && apt-get install -y software-properties-common \
 && add-apt-repository -y ppa:hnakamur/openresty-luajit \
 && add-apt-repository -y ppa:hnakamur/libsxg \
 && add-apt-repository -y ppa:hnakamur/nginx \
 && apt-get update \
 && apt-get install -y luajit libluajit-5.1 libluajit-5.1-common nginx \
        libxmlsec1 libxmlsec1-openssl \
 && ln -s $(readlink /lib/x86_64-linux-gnu/libz.so.1) /lib/x86_64-linux-gnu/libz.so \
 && ln -s $(readlink /usr/lib/x86_64-linux-gnu/libxml2.so.2) /usr/lib/x86_64-linux-gnu/libxml2.so \
 && ln -s $(readlink /usr/lib/x86_64-linux-gnu/libxmlsec1.so.1) /usr/lib/x86_64-linux-gnu/libxmlsec1.so \
 && ln -s $(readlink /usr/lib/x86_64-linux-gnu/libxmlsec1-openssl.so.1) /usr/lib/x86_64-linux-gnu/libxmlsec1-openssl.so \
 && ln -s /usr/lib/x86_64-linux-gnu/libssl.so.1.1 /usr/lib/x86_64-linux-gnu/libssl.so \
 && rm /var/log/nginx/access.log /var/log/nginx/error.log \
 && ln -s /dev/stdout /var/log/nginx/access.log \
 && ln -s /dev/stderr /var/log/nginx/error.log

COPY lib/ /usr/lib/nginx/lua/
COPY test_files/idp/etc/nginx/conf.d /etc/nginx/conf.d/
COPY test_files/idp/etc/nginx/lua /etc/nginx/lua/
COPY test_files/idp/etc/nginx/saml /etc/nginx/saml/
COPY test_files/idp/etc/nginx/nginx.conf /etc/nginx/nginx.conf

RUN apt-get install -y iputils-ping netcat

CMD ["/usr/sbin/nginx", "-g", "daemon off;"]
