return {
    key_attribute_name = "mail",
    redirect = {
        url_after_logout = "/sso/logout-finished"
    },
    request = {
        idp_dest_url = "https://idp.example.com/mock-idp",
        sp_entity_id = "https://sp.example.com/sso",
        sp_saml_finish_url = "https://sp.example.com/sso/finish-login"
    },
    response = {
        id_attr = {
            attrName = "ID", nodeName = "Response",
            nsHref = "urn:oasis:names:tc:SAML:2.0:protocol"
        }
    },
    session = {
        cookie = {
            name = "sso_access_token",
            path = "/",
            secure = true
        },
        store = {
            shared_dict_name = "sso_sessions",
            request_id_expire_seconds = 300,
            request_id_prefix = "_",
            request_id_random_byte_len = 16
        }
    }
}
