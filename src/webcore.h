#ifndef _WEBCORE_H
#define _WEBCORE_H

typedef struct {
    int nref, revision;
    size_t length;
    unsigned char *data;
} streambuffer_t;

typedef struct {
    streambuffer_t *sb;
    int revision;
} streambuffer_ref_t;

streambuffer_t *stb_alloc();
void stb_pull(streambuffer_t *sb, int nb);
streambuffer_t *stb_retain(streambuffer_t *sb);
void stb_unref(streambuffer_t *sb);

#define LXUV_MT_STBUF "WebCore UV StreamBuffer"

#define LXUV_RETAIN(L, i) \
    (lua_pushvalue(L, i), luaL_ref(L, LUA_REGISTRYINDEX));
#define LXUV_RETAIN_THREAD(L) \
    (lua_pushthread(L), luaL_ref(L, LUA_REGISTRYINDEX));
#define LXUV_RELEASE(L, v) if(v != LUA_REFNIL) { \
	luaL_unref(L, LUA_REGISTRYINDEX, v); \
	v = LUA_REFNIL; \
}

#endif
