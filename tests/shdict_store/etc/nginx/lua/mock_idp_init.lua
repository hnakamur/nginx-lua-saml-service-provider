ngx.log(ngx.INFO, 'mock_idp_init.lua start')

;(function()

function readfile(filename)
    local lines = {}
    for line in io.lines(filename) do
        table.insert(lines, line)
    end
    return table.concat(lines, "\n")
end

local config = require "saml.mock_idp.config"
config.response.idp_certificate = readfile('/etc/nginx/idp.example.com.crt')

config.mock_idp = {
    key      = readfile('/etc/nginx/idp.example.com.key'),
    res_tmpl = readfile('/etc/nginx/mock-idp-res-tmpl.xml')
}

end)()

ngx.log(ngx.INFO, 'mock_idp_init.lua end')
