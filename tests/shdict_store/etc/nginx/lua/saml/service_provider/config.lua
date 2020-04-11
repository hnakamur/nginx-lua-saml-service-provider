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
            attrName = "ID",
            nsHref = "urn:oasis:names:tc:SAML:2.0:protocol",
            nodeName = "Response"
        }
    },
    session = {
        cookie = {
            name = "sso_access_token",
            path = "/",
            secure = true
        },
        store = {
            store_type = "shdict", -- or "redis"
            shared_dict_name = "sso_sessions",
            -- store_type = "redis",
            -- redis = {
            --     host = "127.0.0.1",
            --     port = 6379,
            --     connect_timeout_seconds = 1,
            --     send_timeout_seconds = 1,
            --     read_timeout_seconds = 1,
            --     connection_pool_keepalive_seconds = 10,
            --     connection_pool_size = 100,
            -- },
            request_id = {
                prefix = "_",
                random_byte_len = 16,
                issue_max_retry_count = 10,
                expire_seconds = 5 * 60, -- 5 minutes
            },
            jwt_id = {
                prefix = "t",
                random_byte_len = 16,
                issue_max_retry_count = 10,
            },
            jwt_nonce = {
                prefix = "n",
                random_byte_len = 16,
                issue_max_retry_count = 10,
                duration_after_first_use_seconds = 1,
                usable_count = 1,
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
}
