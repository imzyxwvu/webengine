local schar, tconcat, mmin = string.char, table.concat, math.min
local band = (bit32 or bit).band
local core = require "webcore"

local HTTP = {
    serverVer = "WebEngine/17.8",
    defaultDocs = { "index.html" },
    core = core,
    stdErr = io.stderr
}

local MT = {}

HTTP.mimeTypes = {
    atom = "application/atom+xml",
    hqx = "application/mac-binhex40",
    mathml = "application/mathml+xml", doc = "application/msword",
    bin = "application/octet-stream", exe = "application/octet-stream",
    class = "application/octet-stream", so = "application/octet-stream",
    dll = "application/octet-stream", dmg = "application/octet-stream",
    ogg = "application/ogg",
    pdf = "application/pdf",
    ai = "application/postscript",
    eps = "application/postscript", ps = "application/postscript",
    xls = "application/vnd.ms-excel", ppt = "application/vnd.ms-powerpoint",
    rm = "application/vnd.rn-realmedia",
    xhtml = "application/xhtml+xml", xht = "application/xhtml+xml",
    js = "application/x-javascript", lua = "application/x-lua",
    py = "application/x-python", rb = "application/x-ruby",
    latex = "application/x-latex",
    xml = "application/xml", xsl = "application/xml",
    dtd = "application/xml-dtd",
    sh = "application/x-sh",
    swf = "application/x-shockwave-flash",
    xslt = "application/xslt+xml",
    tar = "application/x-tar",
    tcl = "application/x-tcl",
    tex = "application/x-tex",
    zip = "application/zip",
    mid = "audio/midi", midi = "audio/midi", kar = "audio/midi",
    m4a = "audio/mpeg", mp2 = "audio/mpeg", mp3 = "audio/mpeg",
    aif = "audio/x-aiff", aiff = "audio/x-aiff", aifc = "audio/x-aiff",
    m3u = "audio/x-mpegurl", wav = "audio/x-wav",
    bmp = "image/bmp", gif = "image/gif",
    jpeg = "image/jpeg", jpg = "image/jpeg", jpe = "image/jpeg",
    png = "image/png", svg = "image/svg+xml", svgz = "image/svg+xml",
    tiff = "image/tiff", tif = "image/tiff", ico = "image/x-icon",
    ics = "text/calendar", ifb = "text/calendar", css = "text/css",
    html = "text/html", htm = "text/html", rtf = "text/rtf",
    asc = "text/plain", pod = "text/plain", txt = "text/plain",
    sgml = "text/sgml", sgm = "text/sgml",
    tsv = "text/tab-separated-values",
    wml = "text/vnd.wap.wml", wmls = "text/vnd.wap.wmlscript",
    mpeg = "video/mpeg", mpg = "video/mpeg", mpe = "video/mpeg",
    qt = "video/quicktime", mov = "video/quicktime",
    avi = "video/x-msvideo", movie = "video/x-sgi-movie",
}

local statuscodes = {
    [100] = 'Continue', [101] = 'Switching Protocols',
    [200] = 'OK', [201] = 'Created', [202] = 'Accepted',
    [203] = 'Non-Authoritative Information',
    [204] = 'No Content', [205] = 'Reset Content', [206] = 'Partial Content',
    [300] = 'Multiple Choices', [301] = 'Moved Permanently', [302] = 'Found',
    [303] = 'See Other', [304] = 'Not Modified',
    [400] = 'Bad Request', [401] = 'Unauthorized',
    [403] = 'Forbidden', [404] = 'Not Found',
    [405] = 'Method Not Allowed', [406] = 'Not Acceptable',
    [408] = 'Request Time-out', [409] = 'Conflict', [410] = 'Gone',
    [411] = 'Length Required', [412] = 'Precondition Failed',
    [413] = 'Request Entity Too Large', [415] = 'Unsupported Media Type',
    [416] = 'Requested Range Not Satisfiable', [417] = 'Expectation Failed',
    [418] = 'I\'m a teapot', [426] = "Upgrade Required",
    [500] = 'Internal Server Error', [501] = 'Not Implemented',
    [502] = 'Bad Gateway', [503] = 'Service Unavailable',
}

local Response = {}

function Response:stop()
    if self.stillAlive then
        self.stillAlive = false
        self.connection = "close"
        self.stream:close()
        if self.on_close then self:on_close() end
    end
end

function Response:rawWrite(data)
    if not (self.stillAlive and #self.stream) then
        return nil, "stream already closed"
    end
    return self.stream:write(data)
end

function Response:writeHeader(code, headers)
    assert(not self.headerSent, "header already sent")
    assert(statuscodes[code], "illegal status code")
    local head = {
        ("HTTP/1.1 %d %s"):format(code, statuscodes[code]),
        "Connection: " .. self.connection,
        "Server: " .. HTTP.serverVer }
    for k, v in pairs(headers) do
        if type(v) == "table" then
            for i, vv in ipairs(v) do head[#head + 1] = k .. ": " .. vv end
        else head[#head + 1] = k .. ": " .. v end
    end
    head[#head + 1] = "\r\n"
    assert(self:rawWrite(tconcat(head, "\r\n")))
    self.headerSent = code
    if self.connection == "upgrade" then
        self.stillAlive = false
    end
    return self
end

function Response:handled(resource)
    return self:headerSent()
end

function Response:redirectTo(resource)
    return self:writeHeader(302, { ["Content-Length"] = 0, ["Location"] = resource })
end

function Response:displayError(state, content)
    if not self.headerSent then
        local html = content
        if not html then
            html = string.format([[<html><head><title>WebEngine Error %d</title></head>
<body><h1>%d %s</h1></body></html>]], state, state, statuscodes[state])
        end
        self:writeHeader(state, { ["Content-Length"] = #html, ["Content-Type"] = "text/html" })
        self:rawWrite(html)
    end
    self:stop()
end

function Response:serveFile(opts)
    local fp = io.open(opts[1], "rb")
    if fp then
        local len = fp:seek("end")
        local headers = {
            ["Last-Modified"] = opts.lastModified,
            ["Content-Type"] = opts.contentType,
            ["Content-Length"] = len }
        if opts.range then
            local from, to = opts.range:match("^bytes=(%d+)-(%d*)")
            if from and to then
                from, to = tonumber(from) or 0, tonumber(to) or (len - 1)
                if to >= len then
                    fp:close()
                    return self:displayError(416)
                end
                headers["Content-Range"] = ("bytes %d-%d/%d"):format(from, to, len)
                len = to - from + 1
                headers["Content-Length"] = len
            end
            self:writeHeader(headers["Content-Range"] and 206 or 200, headers)
            fp:seek("set", from or 0)
        else
            self:writeHeader(200, headers)
            fp:seek("set", 0)
        end
        while len > 0 do
            local blocklen = mmin(len, 131072)
            local s, err = self:rawWrite(fp:read(blocklen))
            if not s then
                self:stop()
                break
            end
            len = len - blocklen
        end
        fp:close()
    else
        return self:displayError(403)
    end
end

local function pumpStream(from, to)
    while true do
        local stb, err = from:read(core.dup_stb)
        if stb then
            local s, err = to:write(stb)
            if not s then
                from:close()
                break
            end
        else
            to:close()
            break
        end
    end
end

function Response:pipeBidir(stream)
    self.connection = "upgrade"
    if not self.headerSent then
        self:writeHeader(200) -- Works as a HTTP Tunnelling Proxy
    end
    coroutine.resume(coroutine.create(pumpStream), self.stream, stream)
    return pumpStream(stream, self.stream)
end

local WebSocket = {}

function WebSocket:ping()
    assert(self.stillAlive, "connection is down")
    return self:emitFrame("\x89\0") -- opcode PING
end

function WebSocket:read(frame)
    assert(self.stillAlive, "connection is down")
    local reading_op, chunks
    while true do
        local frame, err = self.stream:read(core.decode_wsframe)
        if not frame then
            return nil, err
        end
        if frame[1] == 1 or frame[1] == 2 then
            if frame.FIN then
                return frame[2]
            else
                reading_op = frame[1]
                chunks = { frames[2] }
            end
        elseif frame[1] == 0 then
            if chunks then
                chunks[#chunks + 1] = frame[2]
                if frame.FIN then
                    return table.concat(chunks)
                end
            else
                self:close()
                return nil, "protocol error"
            end
        elseif frame[1] == 9 then
            -- TODO: handle opcode PING
        elseif frame[1] == 0xa then -- ignore PONG
        else
            self:close()
            return nil, "protocol error"
        end
    end
end

function WebSocket:close()
    if self.stillAlive then
        self:emitFrame("\x08\0") -- opcode CLOSE
        self.stillAive = false
    end
end

function WebSocket:writeText(msg)
    return self:emitWithPayload(0x1, msg)
end

function WebSocket:writeData(msg)
    return self:emitWithPayload(0x2, msg)
end

function WebSocket:emitWithPayload(opcode, payload)
    assert(#payload < 65536, "payload too long")
    assert(self.stillAlive, "connection is down")
    local header
    if #payload < 126 then
        header = string.char(0x80 + opcode, #payload)
    else
        header = string.char(0x80 + opcode, 126,
            band(#payload, 0xff00) / 0x100, band(#payload, 0xff))
    end
    return self:emitFrame(header .. payload)
end

function WebSocket:emitFrame(frame)
    local frame_pack = { frame, nil }
    if self.txqueue_tail then
        self.txqueue_tail[2] = frame_pack
    else
        self.txqueue = frame_pack
    end
    self.txqueue_tail = frame_pack
    if self.paused then
        coroutine.resume(self.qdiscTh) -- continue pumping frames
    end
end

function WebSocket:pumpQueue()
    while self.stillAlive do
        self.paused = false
        while self.txqueue do
            local succeeded = self.stream:write(self.txqueue[1])
            if not succeeded then
                self.stillAlive = false -- connection is down
                break
            end
            self.txqueue = self.txqueue[2] -- pop a frame
            if self.txqueue == nil then
                self.txqueue_tail = nil
            end
        end
        self.paused = true
        coroutine.yield() -- yield and wait for more frames
    end
    self.stream:close()
end

MT.Response = { __index = Response }
MT.WebSocket = { __index = WebSocket }

function HTTP.UrlDecode(is)
    return is:gsub("%%([A-Fa-f0-9][A-Fa-f0-9])", function(m) return schar(tonumber(m, 16)) end)
end

function HTTP.ServerVars(req, base)
    local server_vars = base or {
        SERVER_PROTOCOL = "HTTP/1.1",
        CONTENT_TYPE = req.headers["content-type"],
        CONTENT_LENGTH = req.headers["content-length"],
        PATH_INFO = req.resource }
    server_vars.SERVER_SOFTWARE = HTTP.serverVer
    server_vars.REQUEST_URI = req.resource_orig
    server_vars.QUERY_STRING = req.query
    server_vars.REQUEST_METHOD = req.method
    server_vars.REMOTE_ADDR = req.peername
    server_vars.HTTPS = req.tlsver
    for k, v in pairs(req.headers) do
        server_vars["HTTP_" .. k:gsub("%-", "_"):upper()] = v
    end
    return server_vars
end

function HTTP.ServiceLoop(stream, peername, callback)
    while #stream do
        local req, err = stream:read(core.decode_request, 30)
        if not req then return stream:close() end
        req.peername = peername
        req.tlsver = stream:gettlsver()
        local res = setmetatable({
            stream = stream, connection = "close",
            stillAlive = true }, MT.Response )
        if req.headers.connection and req.headers.connection:find("[Kk]eep%-[Aa]live") then
            res.connection = "keep-alive"
        end
        req.resource, req.query = req.resource_orig:match("^([^%?]+)%??(.*)")
        if not req.resource then return res:displayError(400) end
        req.resource = HTTP.UrlDecode(req.resource)
        local postData = tonumber(req.headers["content-length"])
        if postData then
            if postData > 0x200000 then return res:displayError(413) end
            req.post = stream:read(postData)
            if not req.post then return stream:close() end
        end
        local s, err = pcall(callback, req, res)
        if not #stream or not res.stillAlive or res.connection == "upgrade" then return end
        if s then
            if not res.headerSent then
                local result = "Request not caught by any handler."
                res:writeHeader(500, { ["Content-Type"] = "text/plain", ["Content-Length"] = #result })
                res:rawWrite(result)
            end
        else
            print(err)
            if res.headerSent then return res:stop() else
                local result = ([[<!DOCTYPE html><html>
<head><title>HTTP Error 500</title></head><body><h1>500 Internal Server Error</h1><p>%s Error: <strong>%s</strong></p>
<p style="color:#83B;">* This response is generated by %s</p></body></html>]]):format(_VERSION, err, HTTP.serverVer)
                res:writeHeader(500, { ["Content-Type"] = "text/html", ["Content-Length"] = #result })
                res:rawWrite(result)
            end
        end
        if res.connection ~= "keep-alive" then return res:stop() end
    end
end

function HTTP.Listen(addr, port, callback)
    return core.listen(addr, port, 32, function(stream, err)
        local peername = stream:getpeername()
        if not peername then return stream:close() end
        stream:nodelay(true)
        return HTTP.ServiceLoop(stream, peername, callback)
    end)
end

function HTTP.ListenAll(port, callback)
    return core.listen("::", port, 32, function(stream, err)
        local peername = stream:getpeername()
        if not peername then return stream:close() end
        if peername:find("^::ffff:") then
            peername = peername:sub(8, -1) -- Cut IPv4 prefix
        end
        stream:nodelay(true)
        return HTTP.ServiceLoop(stream, peername, callback)
    end)
end

function HTTP.TLSListenAll(port, sslctx, callback)
    return core.listen("::", port, 32, function(stream, err)
        local peername = stream:getpeername()
        if not peername then return stream:close() end
        if peername:find("^::ffff:") then
            peername = peername:sub(8, -1) -- Cut IPv4 prefix
        end
        stream:nodelay(true)
        local tls_ver = stream:read(core.check_tls, 30)
        if not tls_ver then return stream:close() end
        if tls_ver > 0 then
            if not stream:usesslctx(sslctx, true) then
                return stream:close()
            end
        end
        return HTTP.ServiceLoop(stream, peername, callback)
    end)
end

function HTTP.HandleRequest(req, res, vhost)
    local f_path = ""
    local f_attr
    for p in req.resource:gmatch("([^/\\]+)") do
        if p ~= "..." and p ~= ".." and p ~= "." then
            f_path = f_path .. "/" .. p
            f_attr = core.stat(vhost.documentRoot .. f_path)
            if f_attr then
                if f_attr.mode ~= "directory" then break end
            else break end
        end
    end
    if (f_attr and f_attr.mode == "directory") or f_path == "" then
        if req.resource:sub(-1) == "/" then
            local base_path = f_path .. "/"
            for i, v in ipairs(vhost.defaultDocs or HTTP.defaultDocs) do
                f_path = base_path .. v
                f_attr = core.stat(vhost.documentRoot .. f_path)
                if f_attr then break end
            end
        else
            local location = f_path .. "/"
            if #req.query ~= 0 then location = location .. "?" .. req.query end
            return res:redirectTo(location)
        end
    end
    if not f_attr then
        if vhost.notFoundPage then
            f_path = "/" .. vhost.notFoundPage
            f_attr = assert(core.stat(vhost.documentRoot .. f_path), "404 page not found")
        else
            return res:displayError(404, [[<!DOCTYPE html><html>
<head><title>HTTP Error 404</title></head><body><h1>404 Not Found</h1><p>The page you are requesting is non-existent.</p></body></html>]])
        end
    end
    local suffix = f_path:match("%.([A-Za-z0-9]+)$")
    if suffix then suffix = suffix:lower() end
    if vhost.fcgiFilters and vhost.fcgiFilters[suffix] then
        res.connection = "close"
        local firstBlk = true
        HTTP.ProceedRequest(vhost.fcgiFilters[suffix], HTTP.ServerVars(req, {
            SCRIPT_FILENAME = vhost.documentRoot .. f_path,
            SCRIPT_NAME = f_path,
            SERVER_NAME = req.svrname or req.headers["host"],
            DOCUMENT_ROOT = vhost.documentRoot,
            CONTENT_TYPE = req.headers["content-type"],
            CONTENT_LENGTH = req.headers["content-length"],
        }), req.post, function(blk)
            if firstBlk then
                local headEnd, bodyStart = assert(blk:find("\r\n\r\n"))
                local head, status = { }, "200 OK"
                for l in blk:sub(1, headEnd - 1):gmatch("([^\r\n]+)") do
                    local k, v = l:match("^([%a%d%-_]+): ?(.+)$")
                    if k == "Status" then status = v else head[#head + 1] = l end
                end
                res:rawWrite(("HTTP/1.1 %s\r\nServer: %s\r\nConnection: close\r\n"):
                    format(status, HTTP.serverVer))
                res:rawWrite(tconcat(head, "\r\n") .. "\r\n\r\n")
                res.headerSent, firstBlk = 0, false
                if bodyStart >= #blk then return true end
                blk = blk:sub(bodyStart + 1, -1)
            end
            return res:rawWrite(blk)
        end)
        res:stop()
    elseif req.method == "GET" or req.method == "HEAD" then
        local lastModified = os.date ("!%a, %d %b %Y %H:%M:%S GMT", f_attr.modification)
        if req.headers["if-modified-since"] == lastModified then
            res:writeHeader(304, { ["Last-Modified"] = lastModified })
        elseif req.method == "HEAD" then
            res:writeHeader(200, {
                ["Last-Modified"] = lastModified,
                ["Content-Type"] = HTTP.mimeTypes[suffix],
                ["Content-Length"] = f_attr.size })
        else
            return res:serveFile{
                vhost.documentRoot .. f_path,
                lastModified = lastModified,
                range = req.headers.range,
                contentType = HTTP.mimeTypes[suffix] }
        end
    else return res:displayError(405) end
end

function HTTP.AcceptWebSocket(req, res)
    if res.headerSent then
        error("header already sent")
    end
    if not (req.headers.connection and req.headers.upgrade and
            req.headers.connection:find("[Uu]pgrade") and
            req.headers.upgrade:lower() == "websocket") then
        return nil, "upgrade not requested"
    end
    if not req.headers["sec-websocket-key"] then
        return nil, "Sec-WebSocket-Key expected"
    end
    local acceptkey = req.headers["sec-websocket-key"]
    acceptkey = acceptkey .. '258EAFA5-E914-47DA-95CA-C5AB0DC85B11' -- magic
    acceptkey = core.b64encode(core.sha1(acceptkey))
    res.connection = "upgrade"
    res:writeHeader(101, {
        ["Sec-WebSocket-Accept"] = acceptkey,
        ["Upgrade"] = "websocket" })
    local wsobj = setmetatable({
        stillAlive = true,
        qdiscTh = coroutine.create(WebSocket.pumpQueue),
        stream = stream
    }, MT.WebSocket)
    coroutine.resume(wsobj.qdiscTh, wsobj)
    return wsobj
end

function HTTP.ProceedRequest(dest, vars, postdata, outfunc)
    local co = coroutine.running()
    local stream
    if type(dest) == "string" then
        stream = core.pipe_connect(dest, function(...)
            coroutine.resume(co, ...)
        end)
    else
        local watchdog = core.timer_start(function(self)
            stream:close()
            core.close(self)
            coroutine.resume(co, nil, "timeout bad gateway")
        end, 3000, 0)
        stream = core.tcp_connect("127.0.0.1", dest, function(...)
            core.close(watchdog)
            coroutine.resume(co, ...)
        end)
    end
    stream = assert(coroutine.yield())
    local send = function(t, block)
        return assert(stream:write(core.encode_fcgi(t, block)))
    end
    send(1, "\0\3\0\0\0\0\0\0")
    for k, v in pairs(vars) do
        local vl = #v
        if vl > 127 then
            vl = schar(#k,
                band(vl, 0x7F000000) / 0x1000000 + 0x80,
                band(vl, 0xFF0000) / 0x10000,
                band(vl, 0xFF00) / 0x100, band(vl, 0xFF))
        else vl = schar(#k, vl) end
        send(4, vl .. k .. v)
    end
    send(4, "")
    if postdata then
        local sentLength = 0
        while sentLength < #postdata do
            local restLength = #postdata - sentLength
            if restLength > 0xFF00 then
                send(5, postdata:sub(sentLength + 1, sentLength + 0xFF00))
                sentLength = sentLength + 0xFF00
            else
                send(5, postdata:sub(sentLength + 1, sentLength + restLength))
                break
            end
        end -- FCGI_STDIN
    end
    send(5, "")
    while true do
        local block = assert(stream:read(core.decode_fcgi))
        if block[1] == 6 then
            local s = outfunc(block[2])
            if not s then
                send(2, "")
                return stream:close()
            end
        elseif block[1] == 3 then
            return stream:close()
        elseif block[1] == 7 then
            if HTTP.stdErr then HTTP.stdErr:write(block[2]) end
        end
    end
end

function HTTP.ForwardRequest(req, res, addr, port)
    if req.method == "CONNECT" then
        return res:displayError(405)
    end
    local co = coroutine.running()
    local headers = {}
    for k, v in pairs(req.headers) do
        headers[k] = v
    end
    if headers.connection and headers.connection:find("[Uu]pgrade") then
        headers.connection = "close, Upgrade"
    else
        headers.connection = "close"
    end
    headers["x-forwarded-for"] = nil
    local stream
    local watchdog = core.timer_start(function(self)
        stream:close()
        core.close(self)
        coroutine.resume(co, nil, "timeout bad gateway")
    end, 3000, 0)
    stream = core.tcp_connect(addr, port or 80, function(...)
        core.close(watchdog)
        coroutine.resume(co, ...)
    end)
    stream = coroutine.yield()
    if not stream then
        return res:displayError(502)
    end
    local preparedHeaders = {
        string.format("%s %s HTTP/1.1\r\nConnection: close\r\nX-Forwarded-For: %s",
                      req.method, req.resource_orig, req.peername) }
    for k, v in pairs(headers) do
        preparedHeaders[#preparedHeaders + 1] = string.format("%s: %s", k, v)
    end
    preparedHeaders[#preparedHeaders + 1] = "\r\n"
    assert(stream:write(table.concat(preparedHeaders, "\r\n")))
    if headers["content-length"] and req.postData then
        assert(stream:write(req.postData))
    end
    headers = stream:read(core.decode_response)
    if not headers then
        stream:close()
        return res:displayError(502)
    end
    local statusCode = headers[1]
    local connectionMode = (headers.Connection or "close"):lower()
    headers[1], headers.Server, headers.Connection = nil, nil, nil
    if headers["Content-Length"] then
        local restLength = tonumber(headers["Content-Length"])
        headers["Content-Length"] = tostring(restLength)
        res:writeHeader(statusCode, headers)
        while restLength > 0 do
            local chunk, err = stream:read(mmin(restLength, 0x10000))
            if chunk then
                res:rawWrite(chunk)
                restLength = restLength - #chunk
            else
                return res:stop()
            end
        end
    -- TODO: elseif headers["Content-Encoding"] then
    elseif statusCode == 304 then
        res:writeHeader(statusCode, headers)
    elseif statusCode == 101 and connectionMode == "upgrade" then
        res.connection = "upgrade"
        res:writeHeader(statusCode, headers)
        coroutine.resume(coroutine.create(pumpStream), res.stream, stream)
        return pumpStream(res.stream, stream)
    else
        res.connection = "close"
        res:writeHeader(statusCode, headers)
        return pumpStream(stream, res.stream)
    end
end

return HTTP
