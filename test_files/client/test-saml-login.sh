#!/bin/sh
sp_base_url=https://sp
resolves=""

if [ $# -eq 1 -a "$1" = '--verbose' ]; then
    curl_verbose_opt=-v
else
    curl_verbose_opt=
fi

cookie_jar=$(mktemp)
trap "rm $cookie_jar" EXIT

if [ -n "$curl_verbose_opt" ]; then
    set -x
fi
my_curl="curl -sSk $curl_verbose_opt -b $cookie_jar -c $cookie_jar $resolves"

login() {
    url=$1

    saml_response=$($my_curl -L $url)
    saml_response_base64=$(echo "$saml_response" | base64 | tr -d '\n')
    sp_finish_login_url=$(echo "$saml_response" | sed -E -n '/^<samlp:Response/s/.* Destination="([^"]*)".*/\1/p')
    $my_curl -L --data-urlencode "SAMLResponse=$saml_response_base64" $resolves $sp_finish_login_url
}

login $sp_base_url

$my_curl $sp_base_url/foo
$my_curl $sp_base_url/bar

$my_curl -L $sp_base_url/sso/logout

login $sp_base_url/foo
