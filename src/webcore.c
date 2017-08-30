/*
 *    webcore.c
 *    WebEngine Core Library
 *    (c) zyxwvu Shi <imzyxwvu@gmail.com> @ 201708
 */

#include <stdlib.h>
#include <string.h>
#define LUA_LIB
#include <lua.h>
#include <lauxlib.h>
#include <uv.h>
#include <sys/stat.h>
#include "webcore.h"

lua_State *L_Main = NULL;

typedef struct {
    uv_handle_t *data;
    const char *tname;
    int cbref, cbself;
} luaxuv_handle;

#define LXUV_MT_HANDLE "WebCore UV Handle"

streambuffer_t *stb_alloc() {
    streambuffer_t *sb = malloc(sizeof(streambuffer_t));
    if(sb) {
        sb->nref = 1;
        sb->length = 0;
        sb->revision = 0;
        sb->data = NULL;
    }
    return sb;
}

void stb_pull(streambuffer_t *sb, int nb) {
    if(nb >= sb->length) {
        sb->length = 0;
    } else {
        sb->length -= nb;
        memmove(sb->data, sb->data + nb, sb->length);
    }
    sb->data = realloc(sb->data, sb->length);
    sb->revision++;
}

streambuffer_t *stb_retain(streambuffer_t *sb) {
    sb->nref++;
    return sb;
}

void stb_unref(streambuffer_t *sb) {
    if(--sb->nref == 0) {
        free(sb->data);
        free(sb);
    }
}

static int l_stb__index(lua_State *L) {
    streambuffer_ref_t *ref = luaL_checkudata(L, 1, LXUV_MT_STBUF);
    if(lua_isnumber(L, 2)) {
        int idx = lua_tointeger(L, 2);
        if(idx <= 0 || idx > ref->sb->length) {
            return luaL_error(L, "index out of range");
        }
        lua_pushinteger(L, ref->sb->data[idx - 1]);
    } else {
        luaL_checktype(L, 2, LUA_TSTRING);
        lua_pushvalue(L, lua_upvalueindex(1));
        lua_pushvalue(L, 2);
        lua_rawget(L, -2);
    }
    return 1;
}

static int l_stb__len(lua_State *L) {
    streambuffer_ref_t *ref = luaL_checkudata(L, 1, LXUV_MT_STBUF);
    if(ref->revision != ref->sb->revision) {
        return luaL_error(L, "data has changed");
    }
    lua_pushinteger(L, ref->sb->length);
    return 1;
}

static int l_stb__tostring(lua_State *L) {
    streambuffer_ref_t *ref = luaL_checkudata(L, 1, LXUV_MT_STBUF);
    if(ref->revision != ref->sb->revision) {
        return luaL_error(L, "data has changed");
    }
    lua_pushlstring(L, ref->sb->data, ref->sb->length);
    return 1;
}

static int l_stb__gc(lua_State *L) {
    streambuffer_ref_t *ref = lua_touserdata(L, 1);
    stb_unref(ref->sb);
    return 0;
}

static int l_stb_pull(lua_State *L) {
    streambuffer_ref_t *ref = luaL_checkudata(L, 1, LXUV_MT_STBUF);
    int len = luaL_checkinteger(L, 2);
    if(ref->revision != ref->sb->revision) {
        return luaL_error(L, "data has changed");
    }
    stb_pull(ref->sb, len);
    ref->revision = ref->sb->revision;
    return 1;
}

static luaL_Reg lreg_stb_methods[] = {
    { "pull", l_stb_pull },
    { NULL, NULL }
};

void luaxuv_pushstb(lua_State *L, streambuffer_t *sb)
{
    streambuffer_ref_t *ref = lua_newuserdata(L, sizeof(streambuffer_ref_t));
    ref->sb = stb_retain(sb);
    ref->revision = sb->revision;
    luaL_getmetatable(L, LXUV_MT_STBUF);
    lua_setmetatable(L, -2);
}

void luaxuv_pushaddr(lua_State* L, struct sockaddr_storage* address, int addrlen)
{
    char ip[INET6_ADDRSTRLEN];
    int port = 0;
    if (address->ss_family == AF_INET) {
        struct sockaddr_in* addrin = (struct sockaddr_in*)address;
        uv_inet_ntop(AF_INET, &(addrin->sin_addr), ip, addrlen);
        port = ntohs(addrin->sin_port);
    } else if (address->ss_family == AF_INET6) {
        struct sockaddr_in6* addrin6 = (struct sockaddr_in6*)address;
        uv_inet_ntop(AF_INET6, &(addrin6->sin6_addr), ip, addrlen);
        port = ntohs(addrin6->sin6_port);
    }
    lua_pushstring(L, ip);
    lua_pushinteger(L, port);
}

int l_tcp_connect(lua_State *L);
int l_pipe_connect(lua_State *L);

static luaxuv_handle* luaxuv_newuvobj(lua_State *L, uv_handle_t *handle, const char *tn)
{
    luaxuv_handle *obj = lua_newuserdata(L, sizeof(luaxuv_handle));
    register int i;
    obj->data = handle;
    obj->tname = tn;
    obj->cbref = obj->cbself = LUA_REFNIL;
    luaL_getmetatable(L, LXUV_MT_HANDLE);
    lua_setmetatable(L, -2);
    handle->data = obj;
    return obj;
}

static int luaxuv_close(lua_State *L)
{
    luaxuv_handle *obj = luaL_checkudata(L, 1, LXUV_MT_HANDLE);
    if(obj->data) {
        switch(obj->data->type) {
        case UV_TIMER:
            uv_timer_stop((uv_timer_t *)obj->data);
            break;
        case UV_POLL:
            uv_poll_stop((uv_poll_t *)obj->data);
            break;
        case UV_SIGNAL:
            uv_signal_stop((uv_signal_t *)obj->data);
            break;
        }
        uv_close(obj->data, (uv_close_cb)free);
        obj->data = NULL;
        LXUV_RELEASE(L, obj->cbref);
        LXUV_RELEASE(L, obj->cbself);
    }
    return 0;
}

static int luaxuv_handle_tostring(lua_State *L)
{
    luaxuv_handle *obj = luaL_checkudata(L, 1, LXUV_MT_HANDLE);
    lua_pushstring(L, obj->tname);
    return 1;
}

static int luaxuv_handle_len(lua_State *L) // This returns if the handle is closed
{
    luaxuv_handle *obj = luaL_checkudata(L, 1, LXUV_MT_HANDLE);
    lua_pushboolean(L, obj->data ? 1 : 0);
    return 1;
}

static luaL_Reg lreg_handle[] = {
    { "__len", luaxuv_handle_len },
    { "__gc", luaxuv_close },
    { "__tostring", luaxuv_handle_tostring },
    { NULL, NULL }
};

#define luaxuv_CHECK_CLOSED(obj) \
    if(!obj->data) luaL_error(L, "using a closed %s", obj->tname);

static int luaxuv_udp_new(lua_State *L)
{
    uv_udp_t *handle = malloc(sizeof(uv_udp_t));
    register int r = uv_udp_init(uv_default_loop(), handle);
    if(r < 0) {
        free(handle);
        lua_pushstring(L, uv_strerror(r));
        return lua_error(L);
    }
    luaxuv_newuvobj(L, (uv_handle_t *)handle, "UDP");
    return 1;
}

static void udp_send_callback(uv_udp_send_t* req, int status)
{
    free(req);
}

static int luaxuv_udp_send(lua_State *L)
{
    luaxuv_handle *obj = luaL_checkudata(L, 1, LXUV_MT_HANDLE);
    uv_buf_t buf;
    register int r;
    uv_udp_send_t *req;
    const char *ip;
    int port;
    struct sockaddr_storage addr;
    
    luaxuv_CHECK_CLOSED(obj);
    if(UV_UDP != obj->data->type)
        luaL_error(L, "expected a UDP handle, got %s", obj->tname);
    buf.base = (char*)luaL_checklstring(L, 2, (size_t *)&buf.len);
    ip = luaL_checkstring(L, 3);
    port = luaL_checkint(L, 4);
    if(uv_ip4_addr(ip, port, (struct sockaddr_in*)&addr) &&
       uv_ip6_addr(ip, port, (struct sockaddr_in6*)&addr))
        return luaL_error(L, "invalid IP address or port");
    req = malloc(sizeof(*req));
    r = uv_udp_send(req, (uv_udp_t *)obj->data, &buf, 1,
        (struct sockaddr *)&addr, udp_send_callback);
    if(r < 0) {
        free(req);
        lua_pushstring(L, uv_strerror(r));
        return lua_error(L);
    }
    return 0;
}

static int luaxuv_udp_bind(lua_State *L)
{
    luaxuv_handle *obj = luaL_checkudata(L, 1, LXUV_MT_HANDLE);
    const char *ip = luaL_checkstring(L, 2);
    int port = luaL_checkint(L, 3);
    register int r;
    struct sockaddr_storage addr;
    
    luaxuv_CHECK_CLOSED(obj);
    if(UV_UDP != obj->data->type)
        luaL_error(L, "expected a UDP handle, got %s", obj->tname);
    if(uv_ip4_addr(ip, port, (struct sockaddr_in*)&addr) &&
       uv_ip6_addr(ip, port, (struct sockaddr_in6*)&addr))
        return luaL_error(L, "invalid IP address or port");
    r = uv_udp_bind((uv_udp_t *)obj->data, (struct sockaddr *)&addr, 0);
    if(r < 0) {
        lua_pushstring(L, uv_strerror(r));
        return lua_error(L);
    }
    return 0;
}

static void luaxuv_on_simple_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
        buf->base = malloc(suggested_size);
        buf->len = buf->base ? suggested_size : 0;
}

static void luaxuv_on_recv(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags) {
    luaxuv_handle *obj = handle->data;
    if(nread == 0) { free(buf->base); return; }
    lua_rawgeti(L_Main, LUA_REGISTRYINDEX, obj->cbref);
    if (nread >= 0) {
        lua_pushlstring(L_Main, buf->base, nread);
        free(buf->base);
        luaxuv_pushaddr(L_Main, (struct sockaddr_storage*)addr, sizeof(*addr));
        lua_call(L_Main, 3, 0);
    } else {
        free(buf->base);
        lua_pushnil(L_Main);
        lua_pushstring(L_Main, uv_err_name(nread));
        lua_call(L_Main, 2, 0);
    }
}

static int luaxuv_udp_recv_start(lua_State *L)
{
    luaxuv_handle *obj = luaL_checkudata(L, 1, LXUV_MT_HANDLE);
    register int r;

    luaxuv_CHECK_CLOSED(obj);
    if(UV_UDP != obj->data->type)
        luaL_error(L, "expected a UDP handle, got %s", obj->tname);
    luaL_checktype(L, 2, LUA_TFUNCTION);
    if(obj->cbref == LUA_REFNIL) {
        obj->cbref = LXUV_RETAIN(L, 2);
        r = uv_udp_recv_start((uv_udp_t *)obj->data, luaxuv_on_simple_alloc, luaxuv_on_recv);
        if(r < 0) {
            LXUV_RELEASE(L, obj->cbref);
            lua_pushstring(L, uv_strerror(r));
            return lua_error(L);
        }
    } else {
        luaL_unref(L, LUA_REGISTRYINDEX, obj->cbref);
        obj->cbref = LXUV_RETAIN(L, 2);
    }
    return 0;
}

static int luaxuv_udp_recv_stop(lua_State *L)
{
    luaxuv_handle *obj = luaL_checkudata(L, 1, LXUV_MT_HANDLE);
    register int r;
    
    luaxuv_CHECK_CLOSED(obj);
    if(UV_UDP != obj->data->type)
        luaL_error(L, "expected a UDP handle, got %s", obj->tname);
    if(obj->cbref == LUA_REFNIL) return 0;
    LXUV_RELEASE(L, obj->cbref);
    r = uv_udp_recv_stop((uv_udp_t *)obj->data);
    if(r < 0) {
        lua_pushstring(L, uv_strerror(r));
        return lua_error(L);
    }
    return 0;
}

void webcore_init_stream(uv_stream_t* stream, int cbref);

static void luaxuv_on_conn(uv_stream_t* handle, int status)
{
    luaxuv_handle *self = handle->data;
    if(status < 0) {
        lua_rawgeti(L_Main, LUA_REGISTRYINDEX, self->cbref);
        lua_pushnil(L_Main);
        lua_pushstring(L_Main, uv_err_name(status));
        lua_call(L_Main, 2, 0);
    } else {
        uv_tcp_t *stream = malloc(sizeof(uv_tcp_t));
        int r;
        if(!stream) return;
        r = uv_tcp_init(uv_default_loop(), stream);
        if(r < 0) {
            free(stream);
            return;
        }
        r = uv_accept(handle, (uv_stream_t *)stream);
        if(r < 0) {
            uv_close((uv_handle_t *)stream, (uv_close_cb)free);
        } else {
            webcore_init_stream((uv_stream_t *)stream, self->cbref);
        }
    }
}

static int l_listen(lua_State *L)
{
    const char *ip = luaL_checkstring(L, 1);
    int port = luaL_checkinteger(L, 2);
    int backlog = luaL_checkinteger(L, 3);
    struct sockaddr_storage addr;
    uv_tcp_t *stream;
    int r;

    if(uv_ip4_addr(ip, port, (struct sockaddr_in*)&addr) &&
       uv_ip6_addr(ip, port, (struct sockaddr_in6*)&addr))
        return luaL_error(L, "invalid IP address or port");
    luaL_checktype(L, 4, LUA_TFUNCTION);
    if(stream = malloc(sizeof(*stream))) {
        r = uv_tcp_init(uv_default_loop(), stream);
        if(r < 0) {
            free(stream);
            lua_pushstring(L, uv_strerror(r));
            return lua_error(L);
        }
    } else return luaL_error(L, "can't allocate memory");
    r = uv_tcp_bind((uv_tcp_t *)stream, (struct sockaddr *)&addr, 0);
    if(r < 0) { 
        uv_close((uv_handle_t *)stream, (uv_close_cb)free);
        lua_pushstring(L, uv_strerror(r));
        return lua_error(L);    
    } else {
        luaxuv_handle *obj = luaxuv_newuvobj(L, (uv_handle_t *)stream, "TCP");
        obj->cbref = LXUV_RETAIN(L, 4);
        r = uv_listen((uv_stream_t *)stream, backlog, luaxuv_on_conn);
        if(r < 0) { 
            lua_pushcfunction(L, luaxuv_close);
            lua_pushvalue(L, -2);
            lua_call(L, 1, 0);
            lua_pushstring(L, uv_strerror(r));
            return lua_error(L);    
        }
        obj->cbself = LXUV_RETAIN(L, -1);
        return 1;
    }
}

static void luaxuv_on_timer(uv_timer_t* handle) {
    luaxuv_handle *obj = handle->data;
    lua_rawgeti(L_Main, LUA_REGISTRYINDEX, obj->cbref);
    lua_rawgeti(L_Main, LUA_REGISTRYINDEX, obj->cbself);
    lua_call(L_Main, 1, 0);
}

static int luaxuv_timer_start(lua_State *L)
{
    luaxuv_handle *obj;
    register int r;
    int timeout, repeat;
    uv_timer_t *handle;
    
    luaL_checktype(L, 1, LUA_TFUNCTION);
    timeout = luaL_checkint(L, 2);
    repeat = luaL_optint(L, 3, 0);
    handle = malloc(sizeof(uv_timer_t));
    if((r = uv_timer_init(uv_default_loop(), handle)) < 0) {
        free(handle);
        lua_pushstring(L, uv_strerror(r));
        return lua_error(L);
    }
    obj = luaxuv_newuvobj(L, (uv_handle_t *)handle, "Timer");
    
    r = uv_timer_start((uv_timer_t *)obj->data, luaxuv_on_timer, timeout, repeat);
    if(r < 0) {
        lua_pushcfunction(L, luaxuv_close);
        lua_pushvalue(L, -2);
        lua_call(L, 1, 0);
        lua_pushstring(L, uv_strerror(r));
        return lua_error(L);
    }
    obj->cbref = LXUV_RETAIN(L, 1);
    obj->cbself = LXUV_RETAIN(L, -1);
    return 1;
}

static void luaxuv_on_poll(uv_poll_t* handle, int status, int events) {
    luaxuv_handle *obj = handle->data;
    lua_rawgeti(L_Main, LUA_REGISTRYINDEX, obj->cbref);
    lua_rawgeti(L_Main, LUA_REGISTRYINDEX, obj->cbself);
    lua_pushinteger(L_Main, status);
    lua_call(L_Main, 2, 0);
}

static int luaxuv_rpoll_start(lua_State *L)
{
    luaxuv_handle *obj;
    register int r;
    int fd = luaL_checkint(L, 1);
    uv_poll_t *handle;
    
    luaL_checktype(L, 2, LUA_TFUNCTION);
    handle = malloc(sizeof(uv_poll_t));
    if((r = uv_poll_init(uv_default_loop(), handle, fd)) < 0) {
        free(handle);
        lua_pushstring(L, uv_strerror(r));
        return lua_error(L);
    }
    obj = luaxuv_newuvobj(L, (uv_handle_t *)handle, "Poll");
    
    r = uv_poll_start((uv_poll_t *)obj->data, UV_READABLE, luaxuv_on_poll);
    if(r < 0) {
        lua_pushcfunction(L, luaxuv_close);
        lua_pushvalue(L, -2);
        lua_call(L, 1, 0);
        lua_pushstring(L, uv_strerror(r));
        return lua_error(L);
    }
    obj->cbref = LXUV_RETAIN(L, 2);
    obj->cbself = LXUV_RETAIN(L, -1);
    return 1;
}

static void luaxuv_on_signal(uv_signal_t* handle, int signum) {

    luaxuv_handle *obj = handle->data;
    lua_rawgeti(L_Main, LUA_REGISTRYINDEX, obj->cbref);
    lua_rawgeti(L_Main, LUA_REGISTRYINDEX, obj->cbself);
    lua_pushinteger(L_Main, signum);
    lua_call(L_Main, 2, 0);
}

static int luaxuv_signal_start(lua_State *L)
{
    luaxuv_handle *obj;
    register int r;
    int signal = luaL_checkint(L, 1);
    uv_signal_t *handle;
    
    luaL_checktype(L, 2, LUA_TFUNCTION);
    handle = malloc(sizeof(uv_signal_t));
    if((r = uv_signal_init(uv_default_loop(), handle)) < 0) {
        free(handle);
        lua_pushstring(L, uv_strerror(r));
        return lua_error(L);
    }
    obj = luaxuv_newuvobj(L, (uv_handle_t *)handle, "Signal");
    
    r = uv_signal_start((uv_signal_t *)obj->data, luaxuv_on_signal, signal);
    if(r < 0) {
        lua_pushcfunction(L, luaxuv_close);
        lua_pushvalue(L, -2);
        lua_call(L, 1, 0);
        lua_pushstring(L, uv_strerror(r));
        return lua_error(L);
    }
    obj->cbref = LXUV_RETAIN(L, 2);
    obj->cbself = LXUV_RETAIN(L, -1);
    return 1;
}


static int l_get_total_memory(lua_State* L) {
    lua_pushnumber(L, uv_get_total_memory());
    return 1;
}

static int l_update_time(lua_State* L) {
    uv_update_time(uv_default_loop());
    return 0;
}

static int l_set_process_title(lua_State* L) {
    const char* title = luaL_checkstring(L, 1);
    int r = uv_set_process_title(title);
    if(r < 0)  {
        lua_pushstring(L, uv_strerror(r));
        return lua_error(L);
    }
    return 0;
}

static int l_chdir(lua_State* L) {
    int r = uv_chdir(luaL_checkstring(L, 1));
    if(r < 0)  {
        lua_pushstring(L, uv_strerror(r));
        return lua_error(L);
    }
    return 0;
}

static int l_kill(lua_State* L) {
    int pid = luaL_checkinteger(L, 1);
    int signum = luaL_optinteger(L, 2, SIGTERM);
    int r = uv_kill(pid, signum);
    if(r < 0) {
        lua_pushstring(L, uv_strerror(r));
        return lua_error(L);
    }
    return 0;
}

static int l_uptime(lua_State* L) {
    double uptime;
    int r = uv_uptime(&uptime);
    if(r < 0) {
        lua_pushstring(L, uv_strerror(r));
        return lua_error(L);
    }
    lua_pushnumber(L, uptime);
    return 1;
}

static int l_run(lua_State *L)
{
    int r;
    if(L_Main) return luaL_error(L, "calling uv.run in a callback");
    L_Main = L;
    r = uv_run(uv_default_loop(), UV_RUN_DEFAULT);
    L_Main = NULL;
    if(r < 0) {
        lua_pushstring(L, uv_strerror(r));
        return lua_error(L);
    }
    return 0;
}

static int l_run_nowait(lua_State *L)
{
    int r;
    if(L_Main) return luaL_error(L, "calling uv.run_nowait in a callback");
    L_Main = L;
    r = uv_run(uv_default_loop(), UV_RUN_NOWAIT);
    L_Main = NULL;
    if(r < 0) {
        lua_pushstring(L, uv_strerror(r));
        return lua_error(L);
    }
    return 0;
}

static int l_stop(lua_State *L)
{
    uv_stop(uv_default_loop());
    return 0;
}

#define CURRENT_ISUPPER (chunk[i] >= 'A' && chunk[i] <= 'Z')
#define CURRENT_ISLOWER (chunk[i] >= 'a' && chunk[i] <= 'z')
#define CURRENT_ISNUMBER (chunk[i] >= '0' && chunk[i] <= '9')
#define CURRENT_VALUE   chunk + currentBase, i - currentBase

static int l_decode_request(lua_State *L)
{
    const char *chunk;
    int i = 0, currentExpect = 0, currentBase;
    int verbOrKeyLength;
    char headerKey[32];
    streambuffer_ref_t *ref = luaL_checkudata(L, 1, LXUV_MT_STBUF);
    chunk = ref->sb->data;
    if(ref->sb->length > 0x10000)
        return luaL_error(L, "request too long");
    while(i < ref->sb->length) {
        switch(currentExpect) {
            case 0: // expect HTTP method
                if(chunk[i] == ' ') {
                    verbOrKeyLength = i;
                    currentBase = i + 1;
                    currentExpect = 1;
                }
                else if(!CURRENT_ISUPPER)
                    goto on_malformed_header;
                break;
            case 1: // expect resource
                if(chunk[i] == ' ') {
                    lua_createtable(L, 0, 3);
                    lua_pushlstring(L, chunk, verbOrKeyLength);
                    lua_setfield(L, -2, "method");
                    lua_pushlstring(L, CURRENT_VALUE);
                    lua_setfield(L, -2, "resource_orig");
                    currentBase = i + 1;
                    currentExpect = 2;
                }
                else if(chunk[i] >= 0 && chunk[i] < 32)
                    goto on_malformed_header;
                break;
            case 2: // expect HTTP version - HTTP/1.
                if(chunk[i] == '.') {
                    if(i - currentBase != 6 ||
                       chunk[currentBase + 0] != 'H' ||
                       chunk[currentBase + 1] != 'T' ||
                       chunk[currentBase + 2] != 'T' ||
                       chunk[currentBase + 3] != 'P' ||
                       chunk[currentBase + 4] != '/' ||
                       chunk[currentBase + 5] != '1') {
                        goto on_malformed_header;
                    }
                    lua_createtable(L, 0, 8);
                    lua_pushvalue(L, -1);
                    lua_setfield(L, -3, "headers");
                    currentBase = i + 1;
                    currentExpect = 3;
                }
                else if(!CURRENT_ISUPPER &&
                        chunk[i] != '/' && chunk[i] != '1') {
                    goto on_malformed_header;
                }
                break;
            case 3: // expect HTTP subversion
                if(chunk[i] == '\n') {
                    currentBase = i + 1;
                    currentExpect = 4;
                }
                else if(chunk[i] == '\r')
                    currentExpect = 100;
                else if((chunk[i] != '0' && chunk[i] != '1') ||
                        i != currentBase)
                    goto on_malformed_header;
                break;
            case 4: // expect HTTP header key
                if(chunk[i] == ':') {
                    verbOrKeyLength = i - currentBase;
                    currentExpect = 5;
                }
                else if(i == currentBase && chunk[i] == '\n')
                    goto entire_request_decoded;
                else if(i == currentBase && chunk[i] == '\r')
                    currentExpect = 101;
                else if(i - currentBase > 30)
                    goto on_malformed_header;
                else if(CURRENT_ISUPPER)
                    headerKey[i - currentBase] = chunk[i] + 32;
                else if(CURRENT_ISLOWER || chunk[i] == '-' || chunk[i] == '_' ||
                        CURRENT_ISNUMBER)
                    headerKey[i - currentBase] = chunk[i];
                else
                    goto on_malformed_header;
                break;
            case 5: // skip spaces between column and value
                if(chunk[i] != ' ') {
                    currentBase = i;
                    currentExpect = 6;
                }
                break;
            case 6: // expect HTTP header value
                if(!(chunk[i] >= 0 && chunk[i] < 32))
                    break;
                else if(chunk[i] == '\n' || chunk[i] == '\r') {
                    lua_pushlstring(L, headerKey, verbOrKeyLength);
                    lua_pushlstring(L, CURRENT_VALUE);
                    lua_rawset(L, -3);
                    currentBase = i + 1;
                    currentExpect = chunk[i] == '\r' ? 100 : 4;
                    break;
                }
                goto on_malformed_header;
            case 100: // expect \n after '\r'
                if(chunk[i] != '\n') goto on_malformed_header;
                currentBase = i + 1;
                currentExpect = 4;
                break;
            case 101: // expect final \n
                if(chunk[i] != '\n') goto on_malformed_header;
                goto entire_request_decoded;
        }
        i++;
    }
    lua_pushnil(L);
    return 1;
on_malformed_header:
    return luaL_error(L, "request is malformed");
entire_request_decoded:
    lua_pop(L, 1); // remove header table on stack top
    stb_pull(ref->sb, i + 1);
    return 1;
}

static int l_decode_response(lua_State *L)
{
    const char *chunk;
    int i = 0, currentExpect = 0, currentBase = 0, keyLength;
    char headerKey[32];
    streambuffer_ref_t *ref = luaL_checkudata(L, 1, LXUV_MT_STBUF);
    chunk = ref->sb->data;
    if(ref->sb->length > 0x10000)
        return luaL_error(L, "response too long");
    while(i < ref->sb->length) {
        switch(currentExpect) {
            case 0: // expect HTTP version - HTTP/1.
                if(chunk[i] == '.') {
                    if(i - currentBase != 6 ||
                       chunk[currentBase + 0] != 'H' ||
                       chunk[currentBase + 1] != 'T' ||
                       chunk[currentBase + 2] != 'T' ||
                       chunk[currentBase + 3] != 'P' ||
                       chunk[currentBase + 4] != '/' ||
                       chunk[currentBase + 5] != '1') {
                        goto on_malformed_header;
                    }
                    currentBase = i + 1;
                    currentExpect = 1;
                }
                else if(!CURRENT_ISUPPER &&
                        chunk[i] != '/' && chunk[i] != '1')
                    goto on_malformed_header;
                break;
            case 1: // expect HTTP subversion
                if(chunk[i] == ' ') {
                    currentBase = i + 1;
                    currentExpect = 2;
                }
                else if((chunk[i] != '0' && chunk[i] != '1') ||
                        i != currentBase)
                    goto on_malformed_header;
                break;
            case 2: // expect HTTP status code
                if(chunk[i] == ' ') {
                    lua_createtable(L, 1, 8);
                    lua_pushinteger(L, atoi(chunk + currentBase));
                    lua_rawseti(L, -2, 1);
                    currentBase = i + 1;
                    currentExpect = 3;
                }
                else if(!CURRENT_ISNUMBER)
                    goto on_malformed_header;
                break;
            case 3: // skip HTTP status text
                if(chunk[i] == '\n') {
                    currentBase = i + 1;
                    currentExpect = 4;
                }
                else if(chunk[i] == '\r')
                    currentExpect = 100;
                break;
            case 4: // expect HTTP header key
                if(chunk[i] == ':') {
                    keyLength = i - currentBase;
                    currentExpect = 5;
                }
                else if(i == currentBase && chunk[i] == '\n')
                    goto entire_request_decoded;
                else if(i == currentBase && chunk[i] == '\r')
                    currentExpect = 101;
                else if(i - currentBase > 30)
                    goto on_malformed_header;
                else if(CURRENT_ISUPPER || CURRENT_ISLOWER ||
                        CURRENT_ISNUMBER || chunk[i] == '-')
                    headerKey[i - currentBase] = chunk[i];
                else
                    goto on_malformed_header;
                break;
            case 5: // skip spaces between column and value
                if(chunk[i] != ' ') {
                    currentBase = i;
                    currentExpect = 6;
                }
                break;
            case 6: // expect HTTP header value
                if(!(chunk[i] >= 0 && chunk[i] < 32))
                    break;
                else if(chunk[i] == '\n' || chunk[i] == '\r') {
                    lua_pushlstring(L, headerKey, keyLength);
                    lua_pushvalue(L, -1);
                    lua_rawget(L, -3);
                    if(lua_isstring(L, -1)) {
                        lua_pushvalue(L, -2);
                        lua_createtable(L, 2, 0);
                        lua_pushvalue(L, -3);
                        lua_rawseti(L, -2, 1);
                        lua_pushlstring(L, CURRENT_VALUE);
                        lua_rawseti(L, -2, 2);
                        lua_rawset(L, 2);
                        lua_pop(L, 2);
                    }
                    else if(lua_istable(L, -1)) {
                        lua_pushlstring(L, CURRENT_VALUE);
                        lua_rawseti(L, -2, lua_objlen(L, -2) + 1);
                        lua_pop(L, 2);
                    } else {
                        lua_pop(L, 1);
                        lua_pushlstring(L, CURRENT_VALUE);
                        lua_rawset(L, -3);
                    }
                    currentBase = i + 1;
                    currentExpect = chunk[i] == '\r' ? 100 : 4;
                    break;
                }
                goto on_malformed_header;
            case 100: // expect \n after '\r'
                if(chunk[i] != '\n') goto on_malformed_header;
                currentBase = i + 1;
                currentExpect = 4;
                break;
            case 101: // expect final \n
                if(chunk[i] != '\n') goto on_malformed_header;
                goto entire_request_decoded;
        }
        i++;
    }
    lua_pushnil(L);
    return 1;
on_malformed_header:
    return luaL_error(L, "response is malformed");
entire_request_decoded:
    stb_pull(ref->sb, i + 1);
    return 1;
}

static int l_decode_fcgi(lua_State *L)
{
    streambuffer_ref_t *ref = luaL_checkudata(L, 1, LXUV_MT_STBUF);
    size_t payload_length, entire_length = 8;
    unsigned char *data = ref->sb->data;
    if(ref->sb->length < entire_length) {
        lua_pushnil(L);
        return 1;
    }
    payload_length = data[4] * 0x100 + data[5];
    entire_length += payload_length + data[6];
    if(ref->sb->length < entire_length) {
        lua_pushnil(L);
        return 1;
    }
    lua_createtable(L, 2, 0);
    lua_pushinteger(L, data[1]);
    lua_rawseti(L, -2, 1);
    lua_pushlstring(L, ref->sb->data + 8, payload_length);
    lua_rawseti(L, -2, 2);
    stb_pull(ref->sb, entire_length);
    return 1;
}

static int l_decode_wsframe(lua_State *L)
{
    streambuffer_ref_t *ref = luaL_checkudata(L, 1, LXUV_MT_STBUF);
    unsigned char *frame = ref->sb->data;
    int opcode_and_fin, payload_length, masked;
    unsigned char mask[4];
    int expected_length = 2;
    int i;
    if(ref->sb->length < expected_length)
        return lua_pushnil(L), 0;
    opcode_and_fin = frame[0];
    payload_length = frame[1] & 0x7f;
    if(masked = frame[1] & 0x80) expected_length += 4;
    frame += 2;
    if(payload_length == 127) {
        expected_length += 8;
        if(ref->sb->length < expected_length)
            return lua_pushnil(L), 0;
        if(frame[0] != 0 || frame[1] != 0 || frame[2] != 0 ||
           frame[3] != 0 || frame[4] != 0 || frame[5] > 0xf)
            return luaL_error(L, "payload too long");
        payload_length = frame[5] * 0x10000 + frame[6] * 0x100 + frame[7];
        frame += 8;
    }
    else if(payload_length == 126) {
        expected_length += 2;
        if(ref->sb->length < expected_length)
            return lua_pushnil(L), 0;
        payload_length = frame[0] * 0x100 + frame[1];
        frame += 2;
    }
    expected_length += payload_length;
    if(ref->sb->length < expected_length)
        return lua_pushnil(L), 0;
    if(masked) {
        *(uint32_t *)mask = *(uint32_t *)frame;
        frame += 4;
        for(i = 0; i < payload_length; i++)
            frame[i] ^= mask[i % 4];
    }
    lua_createtable(L, 2, 1);
    lua_pushinteger(L, opcode_and_fin & 0xf);
    lua_rawseti(L, -2, 1);
    if(payload_length > 0) {
        lua_pushlstring(L, frame, payload_length);
        lua_rawseti(L, -2, 2);
    }
    lua_pushboolean(L, opcode_and_fin & 0x80);
    lua_setfield(L, -2, "FIN");
    stb_pull(ref->sb, expected_length);
    return 1;
}

static int l_dup_stb(lua_State *L)
{
    streambuffer_ref_t *ref = luaL_checkudata(L, 1, LXUV_MT_STBUF);
    if(ref->sb->length > 0) {
        streambuffer_t *newstb = stb_alloc();
        newstb->data = ref->sb->data;
        newstb->length = ref->sb->length;
        ref->sb->data = NULL;
        ref->sb->length = 0;
        luaxuv_pushstb(L, newstb);
        stb_unref(newstb);
    } else {
        lua_pushnil(L);
    }
    return 1;
}

static int l_check_tls(lua_State *L)
{
    streambuffer_ref_t *ref = luaL_checkudata(L, 1, LXUV_MT_STBUF);
    unsigned char *data = ref->sb->data;
    if(ref->sb->length < 5) {
        lua_pushnil(L);
        return 1;
    }
    if(data[0] == 22) { // is Client Hello
        lua_pushinteger(L, data[1] * 0x100 + data[2]);
    } else {
        lua_pushinteger(L, 0);
    }
    return 1;
}

static int l_decode_any(lua_State *L)
{
    streambuffer_ref_t *ref = luaL_checkudata(L, 1, LXUV_MT_STBUF);
    lua_pushlstring(L, ref->sb->data, ref->sb->length);
    stb_pull(ref->sb, ref->sb->length);
    return 1;
}

static int l_encode_fcgi(lua_State *L)
{
    int optype = luaL_checkinteger(L, 1);
    int length = 0;
    const char *payload;
    streambuffer_t *stb;
    if(!lua_isnoneornil(L, 2))
        payload = luaL_checklstring(L, 2, (size_t *)&length);
    if(length > 0xffff)
        return luaL_error(L, "payload too long");
    if(NULL == (stb = stb_alloc()))
        return luaL_error(L, "memory allocation failure");
    if(NULL == (stb->data = realloc(stb->data, length + 8))) {
        stb_unref(stb);
        return luaL_error(L, "memory allocation failure");
    }
    stb->data[0] = 0x1; // FCGI_VERSION_1
    stb->data[1] = optype;
    stb->data[2] = 0, stb->data[3] = 1; // FCGI_NULL_REQUEST_ID
    stb->data[4] = (length & 0xff00) >> 8, stb->data[5] = length & 0xff;
    stb->data[6] = 0, stb->data[7] = 0;
    memcpy(stb->data + 8, payload, length); 
    stb->length = length + 8;
    luaxuv_pushstb(L, stb);
    stb_unref(stb);
    return 1;
}

#ifdef _WIN32
 #ifndef S_ISDIR
   #define S_ISDIR(mode)  (mode&_S_IFDIR)
 #endif
 #ifndef S_ISREG
   #define S_ISREG(mode)  (mode&_S_IFREG)
 #endif
 #ifndef S_ISLNK
   #define S_ISLNK(mode)  (0)
 #endif
 #ifndef S_ISSOCK
   #define S_ISSOCK(mode)  (0)
 #endif
 #ifndef S_ISFIFO
   #define S_ISFIFO(mode)  (0)
 #endif
 #ifndef S_ISCHR
   #define S_ISCHR(mode)  (mode&_S_IFCHR)
 #endif
 #ifndef S_ISBLK
   #define S_ISBLK(mode)  (0)
 #endif
#endif

#ifdef _WIN32
static const char *mode2string (unsigned short mode) {
#else
static const char *mode2string (mode_t mode) {
#endif
  if ( S_ISREG(mode) )
    return "file";
  else if ( S_ISDIR(mode) )
    return "directory";
  else if ( S_ISLNK(mode) )
        return "link";
  else if ( S_ISSOCK(mode) )
    return "socket";
  else if ( S_ISFIFO(mode) )
        return "named pipe";
  else if ( S_ISCHR(mode) )
        return "char device";
  else if ( S_ISBLK(mode) )
        return "block device";
  else
        return "other";
}

static int l_stat(lua_State *L) {
    struct stat info;
    const char *file = luaL_checkstring (L, 1);

    if (stat(file, &info)) {
        lua_pushnil(L);
        lua_pushstring(L, strerror(errno));
        return 2;
    }
    lua_newtable (L);
    lua_pushstring(L, mode2string (info.st_mode));
    lua_setfield(L, -2, "mode");
    lua_pushinteger(L, (lua_Integer) info.st_mtime);
    lua_setfield(L, -2, "modification");
    lua_pushinteger(L, (lua_Integer) info.st_size);
    lua_setfield(L, -2, "size");
    return 1;
}

static luaL_Reg lreg_main[] = {
    { "connect", l_tcp_connect },
    { "tcp_connect", l_tcp_connect },
    { "pipe_connect", l_pipe_connect },
    { "listen", l_listen },
    { "run", l_run },
    { "run_nowait", l_run_nowait },
    { "stop", l_stop },
    { "new_udp", luaxuv_udp_new },
    { "udp_new", luaxuv_udp_new },
    { "udp_bind", luaxuv_udp_bind },
    { "udp_send", luaxuv_udp_send },
    { "udp_recv_start", luaxuv_udp_recv_start },
    { "udp_recv_stop", luaxuv_udp_recv_stop },
    { "rpoll_start", luaxuv_rpoll_start },
    { "timer_start", luaxuv_timer_start },
    { "signal_start", luaxuv_signal_start },
    { "close", luaxuv_close },
    { "kill", l_kill },
    { "uptime", l_uptime },
    { "update_time", l_update_time },
    { "get_total_memory", l_get_total_memory },
    { "set_process_title", l_set_process_title },
    { "chdir", l_chdir },
    { "decode_request", l_decode_request },
    { "decode_response", l_decode_response },
    { "decode_fcgi", l_decode_fcgi },
    { "decode_wsframe", l_decode_wsframe },
    { "decode_any", l_decode_any },
    { "encode_fcgi", l_encode_fcgi },
    { "dup_stb", l_dup_stb },
    { "check_tls", l_check_tls },
    { "stat", l_stat },
    { NULL, NULL }
};

extern luaL_Reg lreg_codec[];

int luaopen_webcore_stream(lua_State *L);

LUA_API int luaopen_webcore(lua_State *L)
{
    luaopen_webcore_stream(L);

    luaL_newmetatable(L, LXUV_MT_STBUF);
    lua_newtable(L);
    luaL_register(L, NULL, lreg_stb_methods);
    lua_pushcclosure(L, l_stb__index, 1);
    lua_setfield(L, -2, "__index");
    lua_pushcfunction(L, l_stb__gc);
    lua_setfield(L, -2, "__gc");
    lua_pushcfunction(L, l_stb__tostring);
    lua_setfield(L, -2, "__tostring");
    lua_pushcfunction(L, l_stb__len);
    lua_setfield(L, -2, "__len");
    
    luaL_newmetatable(L, LXUV_MT_HANDLE);
    luaL_register(L, NULL, lreg_handle);
    lua_pop(L, 2);
    
    lua_newtable(L);
    luaL_register(L, NULL, lreg_main);
    luaL_register(L, NULL, lreg_codec);
    lua_pushstring(L, uv_version_string());
    lua_setfield(L, -2, "version");
    return 1;
}
