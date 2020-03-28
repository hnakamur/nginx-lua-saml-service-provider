FROM ubuntu:18.04

RUN apt-get update \
 && apt-get install -y curl

COPY test_files/client/test-saml-login.sh /usr/local/bin/
COPY test_files/client/test-and-verify.sh /usr/local/bin/
COPY test_files/client/expected-result.txt /tmp/

CMD ["/usr/local/bin/test-and-verify.sh"]
