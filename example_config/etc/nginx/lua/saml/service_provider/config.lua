return {
    request = {
        idp_dest_url = "https://idp.example.net/sso_redirect",
        sp_entity_id = "https://sp.example.com/sso",
        sp_saml_finish_url = "http://localhost/sso/finish-login",
        request_id_byte_length = 16
    },
    response = {
        xmlsec_command = "/usr/bin/xmlsec1",
        idp_cert_filename = "/usr/local/etc/idp.crt"
    },
    key_attribute_name = "mail",
    session = {
        cookie = {
            name = "sso_session_id",
            path = "/",
            secure = false
        },
        store = {
            dict_name = "sso_sessions",
            id_byte_length = 16,
            expire_seconds = 600
        }
    }
}
