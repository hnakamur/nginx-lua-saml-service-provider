#!/bin/bash
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

urldecode() {
  # NOTE: needs bash for -e option
  echo -e "$(sed 's/+/ /g;s/%\(..\)/\\x\1/g')"
}

login() {
    url=$1

    post_args=$($my_curl -L $url)
    saml_response=$(echo "$post_args" | sed -e 's/SAMLResponse=\(.*\)&.*/\1/' | urldecode | base64 -d)
    #echo "saml_response=$saml_response"
    sp_finish_login_url=$(echo "$saml_response" | sed -E -n '/^<samlp:Response/s/.* Destination="([^"]*)".*/\1/p')
    #echo "sp_finish_login_url=$sp_finish_login_url"
    $my_curl -L --data-raw "$post_args" $resolves $sp_finish_login_url
}

login $sp_base_url

$my_curl $sp_base_url/foo
$my_curl $sp_base_url/bar

$my_curl -L $sp_base_url/sso/logout

login $sp_base_url/foo
