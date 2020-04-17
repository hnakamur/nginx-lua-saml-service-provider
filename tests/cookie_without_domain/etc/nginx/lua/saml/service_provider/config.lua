return {
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
            attrName = "ID",
            nsHref = "urn:oasis:names:tc:SAML:2.0:protocol",
            nodeName = "Response"
        },
        attribute_names = {"mail"},
    },
    session = {
        cookie = {
            name = "sso_access_token",
            path = "/",
            secure = true
        },
        relay_state_cookie = {
            name = "sso_relay_state",
            path = "/",
            secure = true
        },
        request_id = {
            prefix = "_",
            random_byte_len = 16,
            expire_seconds = 5 * 60, -- 5 minutes
        },
        jwt_id = {
            prefix = "t",
            random_byte_len = 16,
        },
        jwt_sign = {
            algorithm = 'HS256',
            current_key_id = 'key_2020_001_cea3cd1220254c3914b3012db9707894',
            keys = {
                ['key_2020_001_cea3cd1220254c3914b3012db9707894'] = 'Ny5qaJJDXNMjOr+MFFnJoM1LSKr+5F5T',
            },
        },
    }
}
