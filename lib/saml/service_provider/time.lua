local _M = {}

function _M.parse_iso8601_utc_time(str)
    -- NOTE: We accept only 'Z' for timezone.
    local year_s, month_s, day_s, hour_s, min_s, sec_s = str:match('(%d%d%d%d)-(%d%d)-(%d%d)T(%d%d):(%d%d):(%d%d)Z')
    if year_s == nil then
        return nil, 'invalid UTC time pattern unmatch'
    end
    local year = tonumber(year_s)
    if year < 1970 then
        return nil, 'invalid year in UTC time'
    end
    local month = tonumber(month_s)
    if month < 1 or 12 < month then
        return nil, 'invalid month in UTC time'
    end
    local day = tonumber(day_s)
    if day < 1 or 31 < day then
        return nil, 'invalid day in UTC time'
    end
    local hour = tonumber(hour_s)
    if hour < 0 or 23 < hour then
        return nil, 'invalid hour in UTC time'
    end
    local min = tonumber(min_s)
    if min < 0 or 59 < min then
        return nil, 'invalid min in UTC time'
    end
    local sec = tonumber(sec_s)
    if sec < 0 or 59 < sec then
        return nil, 'invalid sec in UTC time'
    end
    return os.time{year=year, month=month, day=day, hour=hour, min=min, sec=sec}
end

return _M
