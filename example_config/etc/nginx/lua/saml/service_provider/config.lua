return {
    key_attribute_name = "mail",
    redirect = {
        url_after_login = "/",
        url_after_logout = "/"
    },
    request = {
        idp_dest_url = "https://idp.example.net/sso_redirect",
        sp_entity_id = "https://sp.example.com/sso",
        sp_saml_finish_url = "https://sp.example.com/sso/finish-login",
        request_id_byte_length = 16,
        urls_before_login = {
            dict_name = "sso_redirect_urls",
            expire_seconds = 180
        }
    },
    response = {
        xmlsec_command = "/usr/bin/xmlsec1",
        idp_cert_filename = "/usr/local/etc/idp.crt"
    },
    session = {
        cookie = {
            name = "sso_session_id",
            path = "/",
            secure = true
        },
        store = {
            dict_name = "sso_sessions",
            id_byte_length = 16,
            expire_seconds = 600
        }
    }
}
