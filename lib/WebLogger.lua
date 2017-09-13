local Logger = { }
local OK, DONE, ROW = sqlite3.OK, sqlite3.DONE, sqlite3.ROW

Logger[1] = sqlite3.open(os.getenv("WEBENGINE_LOGDB") or "zywebd-log.db")
assert(Logger[1], "can't open log database")

function Logger:Prepare(sql)
    local stmt = self[1]:prepare(sql)
    if not stmt then error(self[1]:errmsg()) end
    return stmt
end

local assert, ostime, mfloor = assert, os.time, math.floor

function Logger:ExecSQL(sql, ...)
    local stmt = self:Prepare(sql)
    if stmt:bind_values(...) ~= OK then
        stmt:finalize()
        error "can't bind values"
    end
    local r = stmt:step()
    stmt:finalize()
    return DONE == r or ROW == r
end

Logger:ExecSQL[[
CREATE TABLE IF NOT EXISTS requests(
id INTEGER PRIMARY KEY,
ostime INTEGER NOT NULL,
hostname VARCHAR(120),
method VARCHAR(8) NOT NULL,
resource TEXT NOT NULL,
peername VARCHAR(39) NOT NULL
);]]
Logger:ExecSQL[[
CREATE TABLE IF NOT EXISTS meta(
req_id INTEGER NOT NULL,
m_id SMALLINT NOT NULL,
mval VARCHAR(256) NOT NULL
);]]

local requestStmt = Logger:Prepare[[
INSERT INTO requests(ostime, hostname, method, resource, peername)
VALUES(?, ?, ?, ?, ?)]]
local metaStmt = Logger:Prepare[[
INSERT INTO meta(req_id, m_id, mval) VALUES(?, ?, ?)]]

function Logger:appendMeta(liid, m_id, val)
    metaStmt:bind_values(liid, m_id, val)
    metaStmt:step()
    metaStmt:reset()
end

function Logger:saveRequest(req)
    if req.nologging then return end
    assert(OK == requestStmt:bind_values(ostime(), req.headers.host or "~",
        req.method, req.resource_orig, req.peername))
    assert(DONE == requestStmt:step())
    requestStmt:reset()
    local liid = self[1]:last_insert_rowid()
    if req.headers["user-agent"] then
        self:appendMeta(liid, 0x801, req.headers["user-agent"])
    end
    if req.headers["x-forwarded-for"] then
        self:appendMeta(liid, 0x802, req.headers["x-forwarded-for"])
    end
    if req.headers["referer"] then
        self:appendMeta(liid, 0x803, req.headers["referer"])
    end
    return liid
end

return Logger
