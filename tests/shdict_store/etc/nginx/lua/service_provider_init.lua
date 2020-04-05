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

function handle_saml_error(err)
    if err == nil then
        return
    end

    if type(err) == 'string' then
        ngx.log(ngx.ERR, err)
        ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
        return
    end

    if err.log_detail ~= nil then
        ngx.log(err.log_level,
            string.format('saml_error err_code=%s, detail=%s', err.err_code, err.log_detail))
    else
        ngx.log(err.log_level,
            string.format('saml_error err_code=%s', err.err_code))
    end
    ngx.exit(err.status_code)
end

ngx.log(ngx.INFO, 'service_provider_init.lua end')
