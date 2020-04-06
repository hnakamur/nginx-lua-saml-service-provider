#!/bin/bash
set -e

# NOTE: Run this script at the top directory like:
# ./tests/build_and_run.sh

docker build -t ngx-lua-saml-sp-test -f tests/Dockerfile .
docker run --rm -it ngx-lua-saml-sp-test "$@"
