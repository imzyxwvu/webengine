#ifndef _WEBCORE_STREAM_H
#define _WEBCORE_STREAM_H

#include <lua.h>
#include <lauxlib.h>
#include <uv.h>
#include "webcore.h"

#ifndef NO_SSL
#include <openssl/ssl.h>
#endif

extern lua_State *L_Main;

struct webcore_stream;

typedef int (*webcore_streamop_t)(lua_State *, struct webcore_stream *);

typedef struct webcore_stream {
    int ref_decoder, ref_th;
    int ref_ssl_ctx;
    streambuffer_t *sb;
    webcore_streamop_t readfunc, writefunc;
    uv_stream_t *handle;
    uv_timer_t *timeout; // timeout must be available when handle is not NULL
#ifndef NO_SSL
    SSL *ssl;
    BIO *rxbio, *txbio;
#endif
} webcore_stream_t;

void resume_lua_thread(lua_State *th, int narg);
webcore_stream_t *luaxuv_pushstream(lua_State *L, uv_stream_t *handle);
void luaxuv_pushstb(lua_State *L, streambuffer_t *sb);
void luaxuv_pushaddr(lua_State* L, struct sockaddr_storage* address, int addrlen);
webcore_stream_t *webcore_create_stream(lua_State *L);
void webcore_stream_close(lua_State *L, webcore_stream_t *self, const char *reason);

#endif