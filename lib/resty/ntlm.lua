local struct = require("struct")
local cjson = require("cjson")
local iconv = require("iconv")
local NTLMSSP = "NTLMSSP\0"
local NTLMHEADER = "NTLM "

local _M = {
    _VERSION = "0.1"
}

-- debug begin --
local fromhex = function(str)
    return (str:gsub('..', function (cc)
        return string.char(tonumber(cc, 16))
    end))
end
local tohex = function(str)
    return (str:gsub('.', function (c)
        return string.format('%02X', string.byte(c))
    end))
end
-- debug --

-- ASN1 beigin --
local maketlv = function(dertype, payload)
    local len = #payload
    if len < 128 then
        return dertype .. string.char(len) .. payload
    end
    if len < 256 then
        return dertype .. '\x81' .. string.char(len) .. payload
    end
    return dertype .. '\x82' .. struct.pack('>H', len) .. payload
end

local makeint = function(number, tag)
    local payload = ''
    if number == 0 then
       payload = '\x00'
    end
    while number > 0 do
        payload = string.char(bit.band(number, 255)) .. payload
        number = bit.rshift(number, 8)
    end
    return maketlv(tag, payload)
end

local makeenum = function(number)
    return makeint(number, '\x0A')
end

local makeseq = function(payload)
    return maketlv('\x30', payload)
end

local makeoctstr = function(payload)
    return maketlv('\x04', payload)
end

local makegenstr = function(payload)
    return maketlv('\x1b', payload)
end

local makebool = function(payload)
    if payload then
        return maketlv('\x01', '\x7F')
    end
    return maketlv('\x01', '\x00')
end

local parselen = function(berobj)
    local length = string.byte(string.sub(berobj, 2, 2))
    if length < 128 then
        return length, 2
    end
    local nlength = bit.band(length, 0x7f)
    length = 0
    for i=3, 2+nlength do
        length = length * 256 + string.byte(string.sub(berobj, i, i))
    end
    return length, 2 + nlength
end

local parsetlv = function(dertype, derobj, partial)
    if string.sub(derobj, 1, 1) ~= dertype then
        ngx.log(ngx.ERR, "BER element")
    end
    length, pstart = parselen(derobj)
    if partial then
        if #derobj < length+pstart then
            ngx.log(ngx.ERR, "BER payload")
        end
        return string.sub(derobj, pstart+1, pstart+length), string.sub(derobj, pstart+length+1)
    end
    if #derobj ~= (length+pstart) then
        ngx.log(ngx.ERR, "BER payload2")
    end
    return string.sub(derobj, pstart+1), nil
end

local parseint = function(payload, partial, tag)
    local part1, part2 = parsetlv(tag, payload, partial)
    payload = part1
    local value = 0
    assert( bit.band(string.byte(string.sub(payload, 1, 1)), 0x80) == 0x00 )
    for i=1, #payload do
        value = value*256 + string.byte(string.sub(payload, i, i))
    end
    if partial then
        return value, part2
    end
    return value, nil
end

local parseenum = function(payload, partial)
    return parseint(payload, partial, '\x0A')
end

local parseseq = function(payload, partial)
    return parsetlv('\x30', payload, partial)
end

local parseoctstr = function(payload, partial)
    return parsetlv('\x04', payload, partial)
end

local parseset = function(payload, partial)
    return parsetlv('\x31', payload, partial)
end

-- ASN1 end --

local create_proxy = function(_ldap)
    local ldap = string.sub(_ldap, string.len("ldap://") + 1)
    local m, err = ngx.re.match(ldap, "(.*):(.*)", "iu")
    local o = {}
    o.transactionId = 0
    o.authorized = false
    if not err then
        o.server = m[1]
        o.port = tonumber(m[2])
    else
        o.server = ldap
        o.port = 389
    end
    return o
end

local parse_ntlm_authenticate = function(msg)
    local length, offset = struct.unpack('<HxxI', msg, 29)
    local domain = string.sub(msg, offset+1, offset+length)
    length, offset = struct.unpack('<HxxI', msg, 37)
    local username = string.sub(msg, offset+1, offset+length)
    local flags = struct.unpack('<I', msg, 61)
    if bit.band(flags, 0x00000001) == 1 then
        local t = iconv.new('UTF8', 'UTF16LE')
        username = t:iconv(username)
        domain = t:iconv(domain)
    end
    return username, domain
end

local make_session_setup_req = function(ntlm_token, proxy) 
    local authentication = maketlv('\xA3', makeoctstr('GSS-SPNEGO') .. makeoctstr(ntlm_token))
    local k = makeint(3, '\x02') .. makeoctstr("") .. authentication
    local bindRequest = maketlv('\x60', k)
    proxy.transactionId = proxy.transactionId + 1
    return  makeseq(makeint(proxy.transactionId, '\x02') .. bindRequest)
end

local parse_session_setup_resp = function(msg, proxy)
    local data, messageId, controls, resultCode, matchedDN, diagnosticMessage, serverSaslCreds
    data = parseseq(msg)
    messageId, data = parseint(data, true, '\x02')
    if messageId ~= proxy.transactionId then
        ngx.log(ngx.ERR, "Unexpected MessageID: " .. messageId)
    end
    data, controls = parsetlv('\x61', data, true) 
    resultCode, data = parseenum(data, true)
    matchedDN, data = parseoctstr(data, true)
    diagnosticMessage, data = parseoctstr(data, true)
    if resultCode == 0 then
        return true, ''
    end
    if resultCode ~= 14 then
        return false, ''
    end
    serverSaslCreds, data = parsetlv('\x87', data, false)
    return true, serverSaslCreds
end

local ntlm_transaction = function(msg, proxy, timeout)
    local hdr, partial, length, pstart, payload
    local idx = ngx.var.connection
    local option = {pool = proxy.server .. ":" .. proxy.port .. ":" .. idx}
    local sock, err = ngx.socket.connect(proxy.server, proxy.port, option)
    if err then
        ngx.log(ngx.ERR, "Connect fail: " .. err, " server: ", proxy.server, " port: ", proxy.port)
        return nil
    end
    length, err = sock:send(msg)
    if err == nil then
        hdr, err, partial = sock:receive(6)
        length, pstart = parselen(hdr)
    end
    if err == nil then
        payload, err, partial = sock:receive(length+pstart-6)
    end
    if err == nil then
        if timeout > 0 then
            sock:setkeepalive(timeout*1000)
        else
            sock:close()
        end
        return hdr .. payload
    end
    sock:close()
    ngx.log(ngx.ERR, err)
    return nil
end

local decode_http_authorization_header = function(msg, header)
    local m = string.sub(msg, string.len(header) + 1)
    return ngx.decode_base64(m)
end

local ntlm_message_type = function(msg) 
    local header = string.sub(msg, 1, 8)
    if header == NTLMSSP then
        return struct.unpack('<I', msg, 9, 12)
    end
    return -1
end

local ntlm_handle_type1 = function(token, proxy, cache, timeout)
    local ok
    local status = ngx.HTTP_INTERNAL_SERVER_ERROR
    local idx = ngx.var.connection
    local msg = make_session_setup_req(token, proxy)
    -- ngx.log(ngx.ERR, "==start to send type1", " connection id= ", idx)
    msg = ntlm_transaction(msg, proxy, timeout)
    if msg ~= nil then 
        -- ngx.log(ngx.ERR, "==end send type1")
        ok, msg = parse_session_setup_resp(msg, proxy)
        -- ngx.log(ngx.ERR, "==type1 completed")
        if ok then
            cache:set(idx, cjson.encode(proxy), timeout)
            status = ngx.HTTP_UNAUTHORIZED
            ngx.header["WWW-Authenticate"] = NTLMHEADER .. ngx.encode_base64(msg)
        end
    end
    ngx.exit(status)
end

local ntlm_handle_type3 = function(token, proxy, cache, timeout)
    local ok
    local status = ngx.HTTP_INTERNAL_SERVER_ERROR
    local idx = ngx.var.connection
    local username, domain = parse_ntlm_authenticate(token)
    local msg = make_session_setup_req(token, proxy)
    -- ngx.log(ngx.ERR, "--start to send type3", " connection id= ", idx)
    msg = ntlm_transaction(msg, proxy, 0)
    if msg ~= nil then
        -- ngx.log(ngx.ERR, "--end send type3")
        ok, msg = parse_session_setup_resp(msg, proxy)
        -- ngx.log(ngx.ERR, "--type3 completed")
        if ok then
            -- ngx.log(ngx.ERR, "auth succeed")
            proxy.authorized = true
            proxy.username = username
            proxy.domain = domain
            cache:set(idx, cjson.encode(proxy), timeout)
            -- update req headers
            ngx.req.set_header('X-Ntlm-Username', username)
            ngx.req.set_header('X-Ntlm-Domain', domain)
            return
        else
            ngx.log(ngx.ERR, "auth fails. try again")
            ngx.header["WWW-Authenticate"] = "NTLM"
            status = ngx.HTTP_UNAUTHORIZED
        end
    end
    ngx.exit(status)
end

local isAuthorized = function(cache, timeout)
    local idx = ngx.var.connection
    local value = cache:get(idx)
    if value ~= nil then
        local proxy = cjson.decode(value)
        if proxy.authorized == true then
            ngx.req.set_header('X-Ntlm-Username', proxy.username)
            ngx.req.set_header('X-Ntlm-Domain', proxy.domain)
            cache:set(idx, value, timeout)
            return true, proxy
        end
        return false, proxy
    end
    return false, nil
end

function _M.negotiate(ldap, cache, timeout)
    local ok, proxy = isAuthorized(cache, timeout)
    if ok then
        return
    end
    local message = ngx.var.http_Authorization
    if proxy == nil then
        local idx = ngx.var.connection
        proxy = create_proxy(ldap)
        cache:set(idx, cjson.encode(proxy), timeout)
    end
    if message ~= nil and string.sub(message, 1, string.len(NTLMHEADER)) == NTLMHEADER then
        local msg = decode_http_authorization_header(message, NTLMHEADER)
        local ntlm_type = ntlm_message_type(msg)
        if ntlm_type == 1 then
            return ntlm_handle_type1(msg, proxy, cache, timeout)
        elseif ntlm_type == 3 then
            return ntlm_handle_type3(msg, proxy, cache, timeout)
        end 
    end
    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.header["WWW-Authenticate"] = "NTLM"
    ngx.exit(ngx.HTTP_UNAUTHORIZED)
end
return _M
