return {
    key_attribute_name = "mail",
    redirect = {
        url_after_login = "/",
        url_after_logout = "/sso/logout-finished"
    },
    request = {
        idp_dest_url = "https://idp.example.com/mock-idp",
        sp_entity_id = "https://sp.example.com/sso",
        sp_saml_finish_url = "https://sp.example.com/sso/finish-login",
        urls_before_login = {
            dict_name = "sso_redirect_urls",
            expire_seconds = 180
        }
    },
    response = {
--         idp_certificates = {
-- [[-----BEGIN CERTIFICATE-----
-- ...
-- -----END CERTIFICATE-----
-- ]]
--         },
        id_attr = {
            attrName = "ID", nodeName = "Response",
            nsHref = "urn:oasis:names:tc:SAML:2.0:protocol"
        }
    },
    session = {
        cookie = {
            name = "sso_session_id",
            path = "/",
            secure = true
        },
        store = {
            dict_name = "sso_sessions",
            expire_seconds = 600
        }
    }
}
