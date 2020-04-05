ngx.log(ngx.INFO, 'service_provider_init.lua start')

;(function()

function readfile(filename)
    local lines = {}
    for line in io.lines(filename) do
        table.insert(lines, line)
    end
    return table.concat(lines, "\n")
end

local config = require "saml.service_provider.config"
config.response.idp_certificate = readfile('/etc/nginx/idp.example.com.crt')

end)()

ngx.log(ngx.INFO, 'service_provider_init.lua end')
