return {
    key_attribute_name = "mail",
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
    }
}
