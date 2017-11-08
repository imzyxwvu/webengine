/*
 *    webcore_stream.c
 *    WebEngine Abstract Stream
 *    (c) zyxwvu Shi <imzyxwvu@gmail.com> @ 201708
 */

#include <stdlib.h>
#include <string.h>
#include "webcore_stream.h"

static int l_handle_error(lua_State *L) {
    lua_State *th = lua_tothread(L, 1);
    const char *msg = lua_tostring(L, 2);
    luaL_traceback(L, th, msg, 1);
    fprintf(stderr, "[thread 0x%X] %s\n", th, lua_tostring(L, -1));
    return 0;
}

void resume_lua_thread(lua_State *th, int narg)
{
    int s = lua_resume(th, narg);
    if(s && s != LUA_YIELD) {
        lua_pushcfunction(L_Main, l_handle_error);
        lua_pushthread(th);
        lua_pushvalue(th, -2);
        lua_xmove(th, L_Main, 2);
        lua_call(L_Main, 2, 0);
    }
}

static void luaxuv_on_shutdown(uv_shutdown_t* req, int status)
{
    webcore_stream_t *self = req->data;
    lua_State *th;
    uv_close((uv_handle_t *)req->handle, (uv_close_cb)free);
    free(req);
    if(self->timeout) {
        uv_close((uv_handle_t *)self->timeout, (uv_close_cb)free);
        self->timeout = NULL;
    }
    LXUV_RELEASE(L_Main, self->ref_decoder);
    if(self->ref_th != LUA_REFNIL) {
        lua_rawgeti(L_Main, LUA_REGISTRYINDEX, self->ref_th);
        LXUV_RELEASE(L_Main, self->ref_th);
        th = lua_tothread(L_Main, -1);
        lua_pop(L_Main, 1);
        lua_pushnil(th);
        lua_pushlstring(th, "final", 6);
        resume_lua_thread(th, 2);
    }
}

void webcore_stream_close(lua_State *L, webcore_stream_t *self, const char *reason)
{
    if(self->handle) {
        uv_stream_t *handle = self->handle;
        uv_shutdown_t *req = malloc(sizeof(uv_shutdown_t));
        self->handle = NULL; // Mark as closed so it won't be closed again
        req->data = self;
        if(!req || reason || !uv_is_writable(handle) || !self->sb) {
            uv_close((uv_handle_t *)handle, (uv_close_cb)free);
        }
        else if(uv_shutdown(req, handle, luaxuv_on_shutdown) < 0) {
            free(req);
            uv_close((uv_handle_t *)handle, (uv_close_cb)free);
        } else {
            return; // defer removing callbacks
        }
        if(self->timeout) {
            uv_close((uv_handle_t *)self->timeout, (uv_close_cb)free);
            self->timeout = NULL;
        }
        LXUV_RELEASE(L, self->ref_decoder);
        if(self->ref_th != LUA_REFNIL) {
            lua_State *th;
            lua_rawgeti(L, LUA_REGISTRYINDEX, self->ref_th);
            LXUV_RELEASE(L, self->ref_th);
            th = lua_tothread(L, -1);
            lua_pushnil(th);
            if(reason)
                lua_pushstring(th, reason);
            else
                lua_pushlstring(th, "EOF", 3);
            resume_lua_thread(th, 2);
            lua_pop(L, 1);
        }
    }
}

static int l_stream_close(lua_State *L)
{
    webcore_stream_t *self = luaL_checkudata(L, 1, LXUV_MT_STREAM);
    webcore_stream_close(L, self, NULL);
    return 0;
}

static int l_stream_alive(lua_State *L)
{
    webcore_stream_t *self = luaL_checkudata(L, 1, LXUV_MT_STREAM);
    if(self->handle) {
        lua_pushboolean(L, 1);
    } else {
        lua_pushboolean(L, 0);
    }
    return 1;
}

static int l_stream__gc(lua_State *L)
{
    webcore_stream_t *self = luaL_checkudata(L, 1, LXUV_MT_STREAM);
    if(self->handle) {
        uv_close((uv_handle_t *)self->handle, (uv_close_cb)free);
        self->handle = NULL;
        LXUV_RELEASE(L_Main, self->ref_decoder);
        LXUV_RELEASE(L_Main, self->ref_th);
    }
    if(self->timeout) {
        uv_close((uv_handle_t *)self->timeout, (uv_close_cb)free);
        self->timeout = NULL;
    }
#ifndef NO_SSL
    if(self->ssl) {
        SSL_free(self->ssl);
        self->ssl = NULL;
        self->rxbio = NULL;
        self->txbio = NULL;
    }
    LXUV_RELEASE(L_Main, self->ref_ssl_ctx);
#endif
    if(self->sb) {
        stb_unref(self->sb);
        self->sb = NULL;
    }
    return 0;
}

#ifndef NO_SSL

static int l_stream_gettlsver(lua_State *L)
{
    webcore_stream_t *self = luaL_checkudata(L, 1, LXUV_MT_STREAM);
    if(NULL == self->handle)
        return luaL_error(L, "attempt to operate on a closed stream");
    if(self->ssl)
        lua_pushstring(L, SSL_get_version(self->ssl));
    else
        lua_pushnil(L);
    return 1;
}

#else

static int l_stream_gettlsver(lua_State *L)
{
    lua_pushnil(L);
    return 1;
}

#endif

static int l_stream_write(lua_State *L)
{
    webcore_stream_t *self = luaL_checkudata(L, 1, LXUV_MT_STREAM);
    return self->writefunc(L, self);
}

static int l_stream_read(lua_State *L)
{
    struct webcore_stream *self = luaL_checkudata(L, 1, LXUV_MT_STREAM);
    if(!lua_isnumber(L, 2))
        luaL_checktype(L, 2, LUA_TFUNCTION);
    if(self->ref_th != LUA_REFNIL)
        return luaL_error(L, "another thread is reading on the stream");
    if(self->sb->length > 0) {
        if(lua_isfunction(L, 2)) {
            lua_pushvalue(L, 2);
            luaxuv_pushstb(L, self->sb);
            if(lua_pcall(L, 1, 1, 0) != 0) {
                lua_pushnil(L);
                lua_pushvalue(L, -2);
                return 2;
            }
            if(!lua_isnoneornil(L, -1))
                return 1;
        } else {
            int len = lua_tointeger(L, 2);
            if(self->sb->length >= len) {
                lua_pushlstring(L, (char *)self->sb->data, len);
                stb_pull(self->sb, len);
                return 1;
            }
        }
    }
    if(lua_isnumber(L, 2)) {
        if(lua_tointeger(L, 2) == 0) {
            lua_pushlstring(L, "", 0);
            return 1;
        }
    }
    return self->readfunc(L, self);
}

void webcore_init_stream(uv_stream_t* stream, int cbref)
{
    webcore_stream_t *client;
    lua_State *th = lua_newthread(L_Main);
    lua_rawgeti(th, LUA_REGISTRYINDEX, cbref);
    client = luaxuv_pushstream(th, (uv_stream_t *)stream);
    if((client->sb = stb_alloc())) {
        resume_lua_thread(th, 1);
    } else {
        webcore_stream_close(L_Main, client, NULL);
    }
    lua_pop(L_Main, 1);
}

webcore_stream_t *webcore_create_stream(lua_State *L)
{
    webcore_stream_t *self = lua_newuserdata(L, sizeof(webcore_stream_t));
    memset(self, 0, sizeof(webcore_stream_t));
    self->ref_decoder = LUA_REFNIL;
    self->ref_th = LUA_REFNIL;
    self->ref_ssl_ctx = LUA_REFNIL;
    luaL_getmetatable(L, LXUV_MT_STREAM);
    lua_setmetatable(L, -2);
    self->timeout = malloc(sizeof(uv_timer_t));
    if(uv_timer_init(uv_default_loop(), self->timeout) < 0) {
        free(self->timeout);
        self->timeout = NULL;
        luaL_error(L, "failed to setup timer");
        return NULL;
    }
    self->timeout->data = self;
    return self;
}

static luaL_Reg lreg_stream_methods[] = {
    { "gettlsver", l_stream_gettlsver },
    { "read", l_stream_read },
    { "close", l_stream_close },
    { "write", l_stream_write },
    { NULL, NULL }
};

luaL_Reg lreg_uvstream_methods[0];

int luaopen_webcore_stream(lua_State *L) {
    luaL_newmetatable(L, LXUV_MT_STREAM);
    lua_newtable(L);
    luaL_register(L, NULL, lreg_stream_methods);
    luaL_register(L, NULL, lreg_uvstream_methods);
    lua_setfield(L, -2, "__index");
    lua_pushcfunction(L, l_stream__gc);
    lua_setfield(L, -2, "__gc");
    lua_pushcfunction(L, l_stream_alive);
    lua_setfield(L, -2, "__len");
    lua_pop(L, 1);
    return 0;
}

