/*
 *    webcore_stream.c
 *    WebEngine Stream Object
 *    (c) zyxwvu Shi <imzyxwvu@gmail.com> @ 201708
 */

#include <stdlib.h>
#include <lua.h>
#include <lauxlib.h>
#include <uv.h>
#include <string.h>
#include "webcore.h"

#define LXUV_MT_STREAM "WebCore UV Stream"

#define LXUV_FREE_AND_UNREF(func, var) \
    if(var) func(var), var = NULL

#ifndef NO_SSL
#include <openssl/ssl.h>
#endif

typedef struct {
	uv_stream_t *handle;
    // timeout must be available when handle is not NULL
    uv_timer_t *timeout;
	int ref_decoder, ref_th;
	int ref_ssl_ctx;
    streambuffer_t *sb;
#ifndef NO_SSL
	SSL *ssl;
    BIO *rxbio, *txbio;
    int tls_ready;
#endif
} webcore_stream_t;

typedef struct {
	int l_ref, data_ref, ref_th;
	webcore_stream_t *self;
    union {
        uv_connect_t creq;
        uv_write_t wreq;
    };
    char data[0];
} callback_t;

extern lua_State *L_Main;

void luaxuv_pushstb(lua_State *L, streambuffer_t *sb);
void luaxuv_pushaddr(lua_State* L, struct sockaddr_storage* address, int addrlen);

static int l_handle_error(lua_State *L) {
    lua_State *th = lua_tothread(L, 1);
    const char *msg = lua_tostring(L, 2);
    luaL_traceback(L, th, msg, 1);
    fprintf(stderr, "[thread 0x%X] %s\n",
            (unsigned int)th, lua_tostring(L, -1));
    return 0;
}

static void resume_lua_thread(lua_State *th, int narg)
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

static void resume_lua_thread_with_err(lua_State *th, const char *errmsg)
{
    lua_pushnil(th);
    lua_pushstring(th, errmsg);
    resume_lua_thread(th, 2);
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
		lua_pushlstring(th, "closed", 6);
		resume_lua_thread(th, 2);
	}
}

static void webcore_stream_close(lua_State *L, webcore_stream_t *self, const char *reason)
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
    LXUV_FREE_AND_UNREF(stb_unref, self->sb);
	return 0;
}

static void luaxuv_on_write(uv_write_t *req, int status)
{
	callback_t *cb = req->data;
	webcore_stream_t *self = cb->self;
	lua_State *th;
    lua_rawgeti(L_Main, LUA_REGISTRYINDEX, cb->ref_th);
    LXUV_RELEASE(L_Main, cb->ref_th);
    th = lua_tothread(L_Main, -1);
    lua_pop(L_Main, 1);
	free(cb);
	if(NULL == self->handle) {
        resume_lua_thread_with_err(th, "closed");
	} else if(status == 0) {
        lua_pushboolean(th, 1);
		resume_lua_thread(th, 1);
	} else {
        webcore_stream_close(L_Main, self, uv_err_name(status));
		resume_lua_thread_with_err(th, uv_err_name(status));
	}
}

#ifndef NO_SSL
static int l_stream_flush_bio(lua_State *L, webcore_stream_t *self)
{
	uv_buf_t buf;
	callback_t *cb = NULL;
	int r;
    if((buf.len = BIO_ctrl_pending(self->txbio)) <= 0) {
        lua_pushboolean(L, 1);
        return 1;
    }
	if(NULL == (cb = malloc(sizeof(callback_t) + buf.len)))
		return luaL_error(L, "memory allocation failed");
    if(BIO_read(self->txbio, cb->data, buf.len) < buf.len) {
        free(cb);
        return luaL_error(L, "BIO_read failed");
    }
    cb->ref_th = LXUV_RETAIN_THREAD(L);
    cb->self = self;
    cb->wreq.data = cb;
	buf.base = cb->data;
	r = uv_write(&cb->wreq, (uv_stream_t *)self->handle, &buf, 1, luaxuv_on_write);
	if(r < 0) {
        luaL_unref(L, LUA_REGISTRYINDEX, cb->ref_th);
		free(cb);
		lua_pushnil(L);
		lua_pushstring(L, uv_strerror(r));
		return 2;
	}
	return lua_yield(L, 0);
}

static void luaxuv_on_write_freecb(uv_write_t *req, int status)
{
	free(req->data);
}

static int l_stream_flush_bio_on_read(lua_State *L, webcore_stream_t *self)
{
	uv_buf_t buf;
	callback_t *cb = NULL;
	int r;
    if((buf.len = BIO_ctrl_pending(self->txbio)) <= 0) return 0;
	if(NULL == (cb = malloc(sizeof(callback_t) + buf.len))) return UV_ENOMEM;
    BIO_read(self->txbio, cb->data, buf.len);
    cb->self = self;
    cb->wreq.data = cb;
	buf.base = cb->data;
	r = uv_write(&cb->wreq, (uv_stream_t *)self->handle, &buf, 1, luaxuv_on_write_freecb);
	if(r < 0) {
		free(cb);
		return r;
	}
    return 0;
}

static const char *sslerror_to_string(int err_code)
{
    switch (err_code)
    {
        case SSL_ERROR_NONE: return "SSL_ERROR_NONE";
        case SSL_ERROR_ZERO_RETURN: return "SSL_ERROR_ZERO_RETURN";
        case SSL_ERROR_SSL: return "SSL_ERROR_SSL";
        case SSL_ERROR_WANT_READ: return "SSL_ERROR_WANT_READ";
        case SSL_ERROR_WANT_WRITE: return "SSL_ERROR_WANT_WRITE";
        case SSL_ERROR_WANT_X509_LOOKUP: return "SSL_ERROR_WANT_X509_LOOKUP";
        case SSL_ERROR_SYSCALL: return "SSL_ERROR_SYSCALL";
        case SSL_ERROR_WANT_CONNECT: return "SSL_ERROR_WANT_CONNECT";
        case SSL_ERROR_WANT_ACCEPT: return "SSL_ERROR_WANT_ACCEPT";
        default: return "SSL error";
    }
}

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

static int l_stream_getpeerveri(lua_State *L)
{
	webcore_stream_t *self = luaL_checkudata(L, 1, LXUV_MT_STREAM);
	if(NULL == self->handle)
		return luaL_error(L, "attempt to operate on a closed stream");
    if(NULL == self->ssl)
        return luaL_error(L, "no TLS context applied");
    lua_pushboolean(L, SSL_get_verify_result(self->ssl) == X509_V_OK);
    return 1;
}

static int l_stream_usesslctx(lua_State *L)
{
	webcore_stream_t *self = luaL_checkudata(L, 1, LXUV_MT_STREAM);
    int r;
    luaL_checktype(L, 2, LUA_TUSERDATA);
    luaL_checktype(L, 3, LUA_TBOOLEAN);
	if(NULL == self->handle)
		return luaL_error(L, "attempt to operate on a closed stream");
	if(self->ssl)
		return luaL_error(L, "TLS context already applied");
    self->ssl = SSL_new(*(SSL_CTX **)lua_touserdata(L, 2));
    if(NULL == self->ssl)
        return luaL_error(L, "SSL_new failed");
    self->rxbio = BIO_new(BIO_s_mem());
    self->txbio = BIO_new(BIO_s_mem());
    if((NULL == self->rxbio) || (NULL == self->txbio)) {
        SSL_free(self->ssl);
        if(self->rxbio) BIO_free(self->rxbio);
        if(self->txbio) BIO_free(self->txbio);
        return luaL_error(L, "BIO_new(BIO_s_mem()) failed");
    }
    BIO_set_close(self->rxbio, BIO_CLOSE);
    BIO_set_close(self->txbio, BIO_CLOSE);
    // From openssl manpage:
    // If there was already a BIO connected to ssl, BIO_free() will be called.
    SSL_set_bio(self->ssl, self->rxbio, self->txbio);
    if(self->sb) {
        if(self->sb->length > 0) {
            BIO_write(self->rxbio, self->sb->data, self->sb->length);
            stb_pull(self->sb, self->sb->length);
        }
    }
    self->ref_ssl_ctx = LXUV_RETAIN(L, 2);
    if(lua_toboolean(L, 3)) {
        SSL_set_accept_state(self->ssl);
    } else {
        SSL_set_connect_state(self->ssl);
        if(lua_isstring(L, 4))
            SSL_set_tlsext_host_name(self->ssl, lua_tostring(L, 4));
    }
    r = SSL_get_error(self->ssl, SSL_do_handshake(self->ssl));
    // TODO: Handle SSL_ERROR_WANT_READ: Currently implement of async TLS requires
    // calling :read() to finish handshake. This should be done in :usesslctx().
    if(r != SSL_ERROR_WANT_READ && r != SSL_ERROR_WANT_WRITE && r != SSL_ERROR_NONE) {
        lua_pushnil(L);
        lua_pushstring(L, sslerror_to_string(r));
        return 2;
    }
	return l_stream_flush_bio(L, self);
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
	uv_buf_t buf;
	callback_t *cb = NULL;
	int r;
	if(NULL == self->handle)
		return luaL_error(L, "attempt to operate on a closed stream");
    if(lua_isuserdata(L, 2)) {
        streambuffer_ref_t *ref = luaL_checkudata(L, 2, LXUV_MT_STBUF);
        buf.base = ref->sb->data;
        buf.len = ref->sb->length;
    } else {
	    buf.base = (char *) luaL_checklstring(L, 2, (size_t *)&buf.len);
    }
#ifndef NO_SSL
    if(self->ssl) {
        r = SSL_get_error(self->ssl, SSL_write(self->ssl, buf.base, buf.len));
        if(r != SSL_ERROR_WANT_WRITE && r != SSL_ERROR_NONE) {
            lua_pushnil(L);
            lua_pushstring(L, sslerror_to_string(r));
            return 2;
        }
	    return l_stream_flush_bio(L, self);
    }
#endif
	if(NULL == (cb = malloc(sizeof(callback_t) + buf.len)))
		return luaL_error(L, "memory allocation failed");
    cb->ref_th = LXUV_RETAIN_THREAD(L);
    cb->self = self;
    cb->wreq.data = cb;
    memcpy(cb->data, buf.base, buf.len); // Make a copy of data in case GC releases it
    buf.base = cb->data;
	r = uv_write(&cb->wreq, (uv_stream_t *)self->handle, &buf, 1, luaxuv_on_write);
	if(r < 0) {
        luaL_unref(L, LUA_REGISTRYINDEX, cb->ref_th);
		free(cb);
		lua_pushnil(L);
		lua_pushstring(L, uv_strerror(r));
		return 2;
	}
	return lua_yield(L, 0);
}

static void luaxuv_on_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    webcore_stream_t *self = handle->data;
    char *newbuf = realloc(self->sb->data, self->sb->length + suggested_size);
    if(newbuf) {
	    buf->base = newbuf + self->sb->length;
	    buf->len = suggested_size;
        self->sb->data = newbuf;
    } else {
        buf->len = 0;
    }
}

static void luaxuv_on_timeout(uv_timer_t* handle) {
    webcore_stream_t *self = handle->data;
    lua_State *th;
    lua_rawgeti(L_Main, LUA_REGISTRYINDEX, self->ref_th);
    th = lua_tothread(L_Main, -1);
    lua_pop(L_Main, 1);
    if(self->handle)
        uv_read_stop(self->handle);
    uv_timer_stop(handle);
    LXUV_RELEASE(L_Main, self->ref_th);
    LXUV_RELEASE(L_Main, self->ref_decoder);
    lua_pushnil(th);
    lua_pushlstring(th, "timeout", 7);
    resume_lua_thread(th, 2);
}

static void webcore_clear_reading_state(webcore_stream_t *self) {
    uv_read_stop(self->handle);
    uv_timer_stop(self->timeout);
    LXUV_RELEASE(L_Main, self->ref_th);
    LXUV_RELEASE(L_Main, self->ref_decoder);
}

static void luaxuv_on_data(uv_stream_t* handle, ssize_t nread, const uv_buf_t* buf) {
	webcore_stream_t *self = handle->data;
    lua_State *th;
    int r;
    lua_rawgeti(L_Main, LUA_REGISTRYINDEX, self->ref_th);
    th = lua_tothread(L_Main, -1);
    lua_pop(L_Main, 1);
	if (nread > 0) {
#ifndef NO_SSL
        if(self->ssl) {
            char buffer[16384];
            int ndecoded = 0;
            BIO_write(self->rxbio, self->sb->data + self->sb->length, nread);
            while(1) {
                nread = SSL_read(self->ssl, buffer, sizeof(buffer));
                if(nread > 0) {
                    char *newbuf = realloc(self->sb->data, self->sb->length + nread);
                    if(!newbuf) {
                        webcore_clear_reading_state(self);
                        resume_lua_thread_with_err(th, uv_strerror(UV_ENOMEM));
                        return;
                    }
                    self->sb->data = newbuf;
                    memcpy(self->sb->data + self->sb->length, buffer, nread);
                    ndecoded += nread; // More data available
                    self->sb->length += nread;
                } else {
                    r = SSL_get_error(self->ssl, nread);
                    if(r != SSL_ERROR_WANT_READ && r != SSL_ERROR_WANT_WRITE) {
                        webcore_clear_reading_state(self);
                        resume_lua_thread_with_err(th, sslerror_to_string(r));
                        return;
                    }
                    break; // All data in SSL handle is got :)
                }
            }
            if((r = l_stream_flush_bio_on_read(th, self)) < 0) {
                webcore_clear_reading_state(self);
                resume_lua_thread_with_err(th, uv_strerror(r));
                return;
            }
            if(ndecoded == 0) return;
        } else {
            self->sb->length += nread;
        }
#else
        self->sb->length += nread;
#endif
        self->sb->revision++;
		lua_rawgeti(L_Main, LUA_REGISTRYINDEX, self->ref_decoder);
        if(lua_isfunction(L_Main, -1)) {
		    luaxuv_pushstb(L_Main, self->sb);
		    if(lua_pcall(L_Main, 1, 1, 0) != 0) {
                webcore_clear_reading_state(self);
                lua_pushnil(th);
                lua_xmove(L_Main, th, 1);
                resume_lua_thread(th, 2);
                return;
            }
            if(lua_isnoneornil(L_Main, -1)) return;
            webcore_clear_reading_state(self);
            lua_xmove(L_Main, th, 1);
            resume_lua_thread(th, 1);
        } else {
            int len = lua_tointeger(L_Main, -1);
            if(self->sb->length >= len) {
                lua_pushlstring(th, self->sb->data, len);
                stb_pull(self->sb, len);
                webcore_clear_reading_state(self);
                resume_lua_thread(th, 1);
            }
        }
	} else {
		if (nread == UV_EOF) {
            webcore_stream_close(L_Main, self, NULL);
		} else if(nread < 0) {
			webcore_stream_close(L_Main, self, uv_err_name(nread));
		}
	}
}

static int l_stream_read(lua_State *L)
{
	webcore_stream_t *self = luaL_checkudata(L, 1, LXUV_MT_STREAM);
	int r;
    int timeout = 0;
    if(!lua_isnumber(L, 2))
        luaL_checktype(L, 2, LUA_TFUNCTION);
    if(!lua_isnoneornil(L, 3))
        timeout = luaL_checknumber(L, 3) * 1000;
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
                lua_pushlstring(L, self->sb->data, len);
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
	if(NULL == self->handle)
		return luaL_error(L, "attempt to operate on a closed stream");
    self->ref_decoder = LXUV_RETAIN(L, 2);
	self->ref_th = LXUV_RETAIN_THREAD(L);
	r = uv_read_start((uv_stream_t *)self->handle, luaxuv_on_alloc, luaxuv_on_data);
	if(r < 0) {
        LXUV_RELEASE(L, self->ref_th);
        LXUV_RELEASE(L, self->ref_decoder);
		webcore_stream_close(L, self, uv_err_name(r));
		lua_pushnil(L);
		lua_pushstring(L, uv_strerror(r));
		return 2;
	}
    if(timeout > 0)
        uv_timer_start(self->timeout, luaxuv_on_timeout, timeout, 0);
	return lua_yield(L, 0);
}

static int l_stream_getsockname(lua_State *L)
{
	webcore_stream_t *self = luaL_checkudata(L, 1, LXUV_MT_STREAM);
	int addrlen, r;
	struct sockaddr_storage address;
	if(NULL == self->handle)
		return luaL_error(L, "attempt to operate on a closed stream");
	if(UV_TCP != self->handle->type)
		return luaL_error(L, "stream is not a TCP stream");
	addrlen = sizeof(address);
	r = uv_tcp_getsockname(
		(uv_tcp_t *)self->handle,
		(struct sockaddr*)&address, &addrlen);
	if(r < 0) {
		lua_pushnil(L);
		lua_pushstring(L, uv_strerror(r));
		return 2;
	}
	luaxuv_pushaddr(L, &address, addrlen);
	return 2;
}

static int l_stream_getpeername(lua_State *L)
{
	webcore_stream_t *self = luaL_checkudata(L, 1, LXUV_MT_STREAM);
	int addrlen, r;
	struct sockaddr_storage address;
	if(NULL == self->handle)
		return luaL_error(L, "attempt to operate on a closed stream");
	if(UV_TCP != self->handle->type)
		return luaL_error(L, "stream is not a TCP stream");
	addrlen = sizeof(address);
	r = uv_tcp_getpeername(
		(uv_tcp_t *)self->handle,
		(struct sockaddr*)&address, &addrlen);
	if(r < 0) {
		lua_pushnil(L);
		lua_pushstring(L, uv_strerror(r));
		return 2;
	}
	luaxuv_pushaddr(L, &address, addrlen);
	return 2;
}

#ifdef __linux__

#include <linux/netfilter_ipv4.h>

/*
 * libuv doesn't provide this and this is used for my own purpose.
 * This is useful for transparent proxying...
 */

static int l_stream_getorigdst(lua_State *L)
{
	webcore_stream_t *self = luaL_checkudata(L, 1, LXUV_MT_STREAM);
	int addrlen, r;
	struct sockaddr_in6 address;
	uv_os_fd_t fd;
	if(NULL == self->handle)
		return luaL_error(L, "attempt to operate on a closed stream");
	if(UV_TCP != self->handle->type)
		return luaL_error(L, "stream is not a TCP stream");
	r = uv_fileno((uv_handle_t *)self->handle, &fd);
	if(r < 0) {
		lua_pushnil(L);
		lua_pushstring(L, uv_strerror(r));
		return 2;
	}
	addrlen = sizeof(address);
	if (getsockopt(fd, SOL_IP, SO_ORIGINAL_DST,
		(struct sockaddr *)&address, &addrlen) != 0) {
		lua_pushnil(L);
		return 1;
	}
	luaxuv_pushaddr(L, (void*)&address, addrlen);
	return 2;
}

#endif

static int l_stream_set_nodelay(lua_State *L)
{
	webcore_stream_t *self = luaL_checkudata(L, 1, LXUV_MT_STREAM);
	int r;
	if(NULL == self->handle)
		return luaL_error(L, "attempt to operate on a closed stream");
	luaL_checktype(L, 2, LUA_TBOOLEAN);
	if(UV_TCP != self->handle->type)
		return luaL_error(L, "stream is not a TCP stream");
	r = uv_tcp_nodelay((uv_tcp_t *)self->handle, lua_toboolean(L, 2));
	if(r < 0) {
		lua_pushnil(L);
		lua_pushstring(L, uv_strerror(r));
		return 2;
	}
	lua_pushvalue(L, 1);
	return 1;
}

static void luaxuv_on_connect(uv_connect_t* req, int status)
{
	callback_t *cb = (callback_t *)req->data;
	webcore_stream_t *self = cb->self;
	int cb_ref = cb->l_ref, data_ref = cb->data_ref;
	
	free(cb);
	lua_rawgeti(L_Main, LUA_REGISTRYINDEX, cb_ref);
	luaL_unref(L_Main, LUA_REGISTRYINDEX, cb_ref);
	if(status == 0) {
        if(self->sb = stb_alloc()) {
            lua_State *th = lua_newthread(L_Main);
            lua_xmove(L_Main, th, 2);
            lua_pop(th, 1); // Pop the unwanted thread itself
		    lua_rawgeti(th, LUA_REGISTRYINDEX, data_ref);
            LXUV_RELEASE(th, data_ref);
		    resume_lua_thread(th, 1);
        } else {
		    webcore_stream_close(L_Main, self, NULL);
		    lua_pushnil(L_Main);
		    lua_pushstring(L_Main, "failed to allocate StreamBuffer");
		    lua_call(L_Main, 2, 0);
        }
	} else {
		webcore_stream_close(L_Main, self, uv_err_name(status));
		lua_pushnil(L_Main);
		lua_pushstring(L_Main, uv_err_name(status));
		lua_call(L_Main, 2, 0);
	}
}

static webcore_stream_t *luaxuv_pushstream(lua_State *L, uv_stream_t *handle)
{
	webcore_stream_t *self = lua_newuserdata(L, sizeof(webcore_stream_t));
    memset(self, 0, sizeof(webcore_stream_t));
	self->handle = handle;
	self->ref_decoder = LUA_REFNIL;
	self->ref_th = LUA_REFNIL;
	luaL_getmetatable(L, LXUV_MT_STREAM);
	lua_setmetatable(L, -2);
    self->timeout = malloc(sizeof(uv_timer_t));
    if(uv_timer_init(uv_default_loop(), self->timeout) < 0) {
        free(self->timeout);
        self->timeout = NULL;
    }   
	handle->data = self;
    self->timeout->data = self;
	return self;
}

int l_tcp_connect(lua_State *L)
{
	const char *ip = luaL_checkstring(L, 1);
	int port = luaL_checkinteger(L, 2);
	struct sockaddr_storage addr;
	uv_tcp_t *stream;
	int r;

	if(uv_ip4_addr(ip, port, (struct sockaddr_in*)&addr) &&
	   uv_ip6_addr(ip, port, (struct sockaddr_in6*)&addr))
		return luaL_error(L, "invalid IP address or port");
	luaL_checktype(L, 3, LUA_TFUNCTION);
	if(stream = malloc(sizeof(*stream))) {
		r = uv_tcp_init(uv_default_loop(), stream);
		if(r < 0) {
			free(stream);
			lua_pushstring(L, uv_strerror(r));
			return lua_error(L);
		}
	} else return luaL_error(L, "can't allocate memory");
	{
		webcore_stream_t *self = luaxuv_pushstream(L, (uv_stream_t *)stream);
		callback_t *cb = malloc(sizeof(callback_t));
        cb->data_ref = LXUV_RETAIN(L, -1);
		cb->l_ref = LXUV_RETAIN(L, 3);
		cb->self = self;
		cb->creq.data = cb;
		r = uv_tcp_connect(&cb->creq, stream, (struct sockaddr *)&addr, luaxuv_on_connect);
		if(r < 0) {
			luaL_unref(L, LUA_REGISTRYINDEX, cb->data_ref);
			luaL_unref(L, LUA_REGISTRYINDEX, cb->l_ref);
			free(cb);
			webcore_stream_close(L, self, uv_err_name(r));
			lua_pushstring(L, uv_strerror(r));
			return lua_error(L);
		}
		return 1;
	}
}

int l_pipe_connect(lua_State *L)
{
	const char *name = luaL_checkstring(L, 1);
	uv_pipe_t *stream;
	int r;

	luaL_checktype(L, 2, LUA_TFUNCTION);
	if(stream = malloc(sizeof(*stream))) {
		r = uv_pipe_init(uv_default_loop(), stream, 0);
		if(r < 0) {
			free(stream);
			lua_pushstring(L, uv_strerror(r));
			return lua_error(L);
		}
	} else return luaL_error(L, "can't allocate memory");
	{
		webcore_stream_t *self = luaxuv_pushstream(L, (uv_stream_t *)stream);
		callback_t *cb = malloc(sizeof(callback_t));
        cb->data_ref = LXUV_RETAIN(L, -1);
		cb->l_ref = LXUV_RETAIN(L, 2);
		cb->self = self;
		cb->creq.data = cb;
		uv_pipe_connect(&cb->creq, stream, name, luaxuv_on_connect);
		return 1;
	}
}

void webcore_init_stream(uv_stream_t* stream, int cbref)
{
	webcore_stream_t *client;
    lua_State *th = lua_newthread(L_Main);
	lua_rawgeti(th, LUA_REGISTRYINDEX, cbref);
	client = luaxuv_pushstream(th, (uv_stream_t *)stream);
    if(client->sb = stb_alloc()) {
	    resume_lua_thread(th, 1);
    } else {
        webcore_stream_close(L_Main, client, NULL);
    }
    lua_pop(L_Main, 1);
}

static luaL_Reg lreg_stream_methods[] = {
	{ "getsockname", l_stream_getsockname },
	{ "getpeername", l_stream_getpeername },
#ifdef __linux__
	{ "getorigdst", l_stream_getorigdst },
#endif
	{ "gettlsver", l_stream_gettlsver },
#ifndef NO_SSL
	{ "getpeerveri", l_stream_getpeerveri },
	{ "usesslctx", l_stream_usesslctx },
#endif
	{ "nodelay", l_stream_set_nodelay },
	{ "read", l_stream_read },
	{ "close", l_stream_close },
	{ "write", l_stream_write },
	{ NULL, NULL }
};

int luaopen_webcore_stream(lua_State *L) {
	luaL_newmetatable(L, LXUV_MT_STREAM);
	lua_newtable(L);
	luaL_register(L, NULL, lreg_stream_methods);
	lua_setfield(L, -2, "__index");
	lua_pushcfunction(L, l_stream__gc);
	lua_setfield(L, -2, "__gc");
	lua_pushcfunction(L, l_stream_alive);
	lua_setfield(L, -2, "__len");
	lua_pop(L, 1);
    return 0;
}

