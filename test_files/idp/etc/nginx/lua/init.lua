(function()

function readfile(filename)
    local lines = {}
    for line in io.lines(filename) do
        table.insert(lines, line)
    end
    return table.concat(lines, "\n")
end

local config = require "saml.service_provider.config"
config.response.idp_certificate = readfile('/etc/nginx/saml/idp.example.com.crt')

config.mock_idp = {
    key      = readfile('/etc/nginx/saml/idp.example.com.key'),
    res_tmpl = readfile('/etc/nginx/saml/res-tmpl.xml')
}

end)()
