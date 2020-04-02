return {
    key_attribute_name = "mail",
    redirect = {
        url_after_logout = "/sso/logout-finished"
    },
    request = {
        idp_dest_url = "https://idp/mock-idp",
        sp_entity_id = "https://sp/sso",
        sp_saml_finish_url = "https://sp/sso/finish-login"
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
--    session = {
--        cookie = {
--            name = "sso_session_id",
--            path = "/",
--            secure = true
--        },
--        store = {
--            dict_name = "sso_sessions"
--        }
--    }
    session = {
        cookie = {
            name = "sso_access_token",
            path = "/",
            secure = true
        },
        store = {
            jwt = {
                symmetric_key = 'Ny5qaJJDXNMjOr+MFFnJoM1LSKr+5F5T',
                algorithm = 'HS256'
            }
        }
    }
}