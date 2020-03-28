#!/bin/sh
test-saml-login.sh | tee /tmp/actual-result.txt
if cmp /tmp/actual-result.txt /tmp/expected-result.txt; then
    echo "Test result matched, OK!"
else
    echo "Test result unmatch to expected-result.txt, here is diff:"
    diff -u /tmp/actual-result.txt /tmp/expected-result.txt
fi
