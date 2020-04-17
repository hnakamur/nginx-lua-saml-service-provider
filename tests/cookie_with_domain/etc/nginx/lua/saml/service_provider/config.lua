return {
    request = {
        idp_dest_url = "https://idp.example.com/mock-idp",
        sp_entity_id = "https://sp.example.com/sso",
        sp_saml_finish_url = "https://sp.example.com/sso/finish-login",
        id = {
            prefix = "_",
            random_byte_len = 16,
            expire_seconds = 5 * 60, -- 5 minutes
        },
        cookie = {
            name = "sso_request",
            path = "/",
            domain = "example.com",
        },
    },
    response = {
        id_attr = {
            attrName = "ID",
            nsHref = "urn:oasis:names:tc:SAML:2.0:protocol",
            nodeName = "Response"
        },
        attribute_names = {"mail"},
    },
    access_token = {
        cookie = {
            name = "sso_access_token",
            path = "/",
            domain = "example.com",
        },
    },
    jwt = {
        jti = {
            prefix = "t",
            random_byte_len = 16,
        },
        sign = {
            algorithm = 'HS256',
            current_key_id = 'key_2020_001_cea3cd1220254c3914b3012db9707894',
            keys = {
                ['key_2020_001_cea3cd1220254c3914b3012db9707894'] = 'Ny5qaJJDXNMjOr+MFFnJoM1LSKr+5F5T',
            },
        },
    },
    logout = {
        redirect_url = "/sso/logout-finished"
    },
}
