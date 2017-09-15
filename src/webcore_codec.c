/*
 *    webcore_codec.c
 *    WebEngine Codec Library
 *    (c) zyxwvu Shi <imzyxwvu@gmail.com> @ 201708
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#define LUA_LIB
#include <lua.h>
#include <lauxlib.h>

#define rotate(D, num)  (D<<num) | (D>>(32-num))
#define F(x, y, z) (((x) & (y)) | ((~(x)) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~(z))))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~(z))))

static const uint32_t T[64]={
                     0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
                     0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
                     0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
                     0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
                     0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
                     0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
                     0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
                     0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
                     0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
                     0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
                     0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
                     0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
                     0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
                     0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
                     0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
                     0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

/*funcao que implemeta os quatro passos principais do algoritmo MD5 */
static void md5digest(const uint32_t *m, uint32_t *d) {
  int j;
  /*MD5 PASSO1 */
  for (j=0; j<4*4; j+=4) {
    d[0] = d[0]+ F(d[1], d[2], d[3])+ m[j] + T[j];       d[0]=rotate(d[0], 7);
    d[0]+=d[1];
    d[3] = d[3]+ F(d[0], d[1], d[2])+ m[(j)+1] + T[j+1]; d[3]=rotate(d[3], 12);
    d[3]+=d[0];
    d[2] = d[2]+ F(d[3], d[0], d[1])+ m[(j)+2] + T[j+2]; d[2]=rotate(d[2], 17);
    d[2]+=d[3];
    d[1] = d[1]+ F(d[2], d[3], d[0])+ m[(j)+3] + T[j+3]; d[1]=rotate(d[1], 22);
    d[1]+=d[2];
  }
  /*MD5 PASSO2 */
  for (j=0; j<4*4; j+=4) {
    d[0] = d[0]+ G(d[1], d[2], d[3])+ m[(5*j+1)&0x0f] + T[(j-1)+17];
    d[0] = rotate(d[0],5);
    d[0]+=d[1];
    d[3] = d[3]+ G(d[0], d[1], d[2])+ m[((5*(j+1)+1)&0x0f)] + T[(j+0)+17];
    d[3] = rotate(d[3], 9);
    d[3]+=d[0];
    d[2] = d[2]+ G(d[3], d[0], d[1])+ m[((5*(j+2)+1)&0x0f)] + T[(j+1)+17];
    d[2] = rotate(d[2], 14);
    d[2]+=d[3];
    d[1] = d[1]+ G(d[2], d[3], d[0])+ m[((5*(j+3)+1)&0x0f)] + T[(j+2)+17];
    d[1] = rotate(d[1], 20);
    d[1]+=d[2];
  }
  /*MD5 PASSO3 */
  for (j=0; j<4*4; j+=4) {
    d[0] = d[0]+ H(d[1], d[2], d[3])+ m[(3*j+5)&0x0f] + T[(j-1)+33];
    d[0] = rotate(d[0], 4);
    d[0]+=d[1];
    d[3] = d[3]+ H(d[0], d[1], d[2])+ m[(3*(j+1)+5)&0x0f] + T[(j+0)+33];
    d[3] = rotate(d[3], 11);
    d[3]+=d[0];
    d[2] = d[2]+ H(d[3], d[0], d[1])+ m[(3*(j+2)+5)&0x0f] + T[(j+1)+33];
    d[2] = rotate(d[2], 16);
    d[2]+=d[3];
    d[1] = d[1]+ H(d[2], d[3], d[0])+ m[(3*(j+3)+5)&0x0f] + T[(j+2)+33];
    d[1] = rotate(d[1], 23);
    d[1]+=d[2];
  }
  /*MD5 PASSO4 */
  for (j=0; j<4*4; j+=4) {
    d[0] = d[0]+ I(d[1], d[2], d[3])+ m[(7*j)&0x0f] + T[(j-1)+49];
    d[0] = rotate(d[0], 6);
    d[0]+=d[1];
    d[3] = d[3]+ I(d[0], d[1], d[2])+ m[(7*(j+1))&0x0f] + T[(j+0)+49];
    d[3] = rotate(d[3], 10);
    d[3]+=d[0];
    d[2] = d[2]+ I(d[3], d[0], d[1])+ m[(7*(j+2))&0x0f] + T[(j+1)+49];
    d[2] = rotate(d[2], 15);
    d[2]+=d[3];
    d[1] = d[1]+ I(d[2], d[3], d[0])+ m[(7*(j+3))&0x0f] + T[(j+2)+49];
    d[1] = rotate(d[1], 21);
    d[1]+=d[2];
  }
}

/*
** returned status:
*  0 - normal message (full 64 bytes)
*  1 - enough room for 0x80, but not for message length (two 4-byte words)
*  2 - enough room for 0x80 plus message length (at least 9 bytes free)
*/
static int md5convert (uint32_t *x, const char *pt, int num, int old_status) {
  int new_status = 0;
  char buff[64];
  int i;
  if (num<64) {
    memcpy(buff, pt, num);  /* to avoid changing original string */
    memset(buff+num, 0, 64-num);
    if (old_status == 0)
      buff[num] = '\200';
    new_status = 1;
    pt = buff;
  }
  for (i=0; i<16; i++) {
    int j=i*4;
    x[i] = (((uint32_t)(unsigned char)pt[j+3] << 8 |
           (uint32_t)(unsigned char)pt[j+2]) << 8 |
           (uint32_t)(unsigned char)pt[j+1]) << 8 |
           (uint32_t)(unsigned char)pt[j];
  }
  if (num <= (64 - 9))
    new_status = 2;
  return new_status;
}

static void md5 (const char *message, long len, char *output) {
  uint32_t d[4];
  uint32_t *input = d;
  int status = 0;
  long i = 0;
  d[0] = 0x67452301; // init_digest
  d[1] = 0xEFCDAB89;
  d[2] = 0x98BADCFE;
  d[3] = 0x10325476;
  while (status != 2) {
    uint32_t d_old[4];
    uint32_t wbuff[16];
    int numbytes = (len-i >= 64) ? 64 : len-i;
    /*salva os valores do vetor digest*/
    d_old[0]=d[0]; d_old[1]=d[1]; d_old[2]=d[2]; d_old[3]=d[3];
    status = md5convert(wbuff, message+i, numbytes, status);
    if (status == 2) {
      wbuff[14] = (uint32_t)((len<<3) & 0xFFFFFFFF);
      wbuff[15] = (uint32_t)(len>>(32-3) & 0x7);
    }
    md5digest(wbuff, d);
    d[0]+=d_old[0]; d[1]+=d_old[1]; d[2]+=d_old[2]; d[3]+=d_old[3];
    i += numbytes;
  }
  i = 0;
  while (i<4*4) {
    uint32_t v = *input++;
    output[i++] = (char)(v & 0xff); v >>= 8;
    output[i++] = (char)(v & 0xff); v >>= 8;
    output[i++] = (char)(v & 0xff); v >>= 8;
    output[i++] = (char)(v & 0xff);
  }
}

typedef struct {
    unsigned char S[256];
    int i, j;
} rc4_state;

static int lrc4_proceed(lua_State *L)
{
    rc4_state *rc4;
    size_t len;
    const unsigned char *input = (const unsigned char *)luaL_checklstring(L, 1, &len);
    unsigned char *output;
    int i, j;
    luaL_checktype(L, lua_upvalueindex(1), LUA_TUSERDATA);
    if(len == 0) {
        lua_pushliteral(L, "");
        return 1;
    }
    rc4 = lua_touserdata(L, lua_upvalueindex(1));
    output = malloc(len);
    if(NULL == output)
        return luaL_error(L, "can't allocate a buffer of %d bytes", len);
    for(i = 0; i < len; i++) {
        rc4->i = (rc4->i + 1) % 256; rc4->j = (rc4->j + rc4->S[rc4->i]) % 256;
        j = rc4->S[rc4->i]; rc4->S[rc4->i] = rc4->S[rc4->j]; rc4->S[rc4->j] = j;
        output[i] = input[i] ^ rc4->S[(rc4->S[rc4->i] + rc4->S[rc4->j]) % 256];
    }
    lua_pushlstring(L, output, len);
    free(output);
    return 1;
}

static int l_newrc4(lua_State *L)
{
    rc4_state *rc4;
    int init_i = luaL_optinteger(L, 2, 0);
    if(lua_type(L, 1) == LUA_TTABLE) {
        int i;
        if(lua_objlen(L, 1) != 256)
            return luaL_error(L, "length of the initial S must be 256");
        rc4 = (rc4_state *) lua_newuserdata(L, sizeof(rc4_state));
        for(i = 0; i < 256; i++) {
            lua_rawgeti(L, 1, i + 1);
            rc4->S[i] = lua_tointeger(L, -1);
            lua_pop(L, 1);
        }
    } else {
        size_t len;
        const char *S = luaL_checklstring(L, 1, &len);
        if(len != 256)
            return luaL_error(L, "length of the initial S must be 256");
        rc4 = (rc4_state *) lua_newuserdata(L, sizeof(rc4_state));
        memcpy(rc4->S, S, 256);
    }
    rc4->i = init_i; rc4->j = 0;
    lua_pushcclosure(L, lrc4_proceed, 1);
    return 1;
}

static const char b64code[]=
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void b64encode(luaL_Buffer *b, unsigned int c1, unsigned int c2, unsigned int c3, int n)
{
    unsigned long tuple = c3+256UL*(c2+256UL*c1);
    int i;
    char s[4];
    for (i=0; i<4; i++) {
        s[3-i] = b64code[tuple % 64];
        tuple /= 64;
    }
    for (i=n+1; i<4; i++) s[i]='=';
    luaL_addlstring(b,s,4);
}

static int l_b64encode(lua_State *L)        /** encode(s) */
{
    size_t l;
    const unsigned char *s = (const unsigned char*)luaL_checklstring(L,1,&l);
    luaL_Buffer b;
    int n;
    luaL_buffinit(L,&b);
    for (n=l/3; n--; s+=3)
        b64encode(&b,s[0],s[1],s[2],3);
    switch (l%3)
    {
        case 1: b64encode(&b,s[0],0,0,1); break;
        case 2: b64encode(&b,s[0],s[1],0,2); break;
    }
    luaL_pushresult(&b);
    return 1;
}

static void b64decode(luaL_Buffer *b, int c1, int c2, int c3, int c4, int n)
{
    unsigned long tuple=c4+64L*(c3+64L*(c2+64L*c1));
    char s[3];
    switch (--n)
    {
        case 3: s[2]=tuple;
        case 2: s[1]=tuple >> 8;
        case 1: s[0]=tuple >> 16;
    }
    luaL_addlstring(b,s,n);
}

static int l_b64decode(lua_State *L)        /** decode(s) */
{
    size_t l;
    const char *s=luaL_checklstring(L,1,&l);
    luaL_Buffer b;
    int n=0;
    char t[4];
    luaL_buffinit(L,&b);
    for (;;) {
        int c=*s++;
        switch (c)
        {
            const char *p;
            default:
                p=strchr(b64code,c); if (p==NULL) return 0;
                t[n++]= p-b64code;
                if (n==4) {
                    b64decode(&b,t[0],t[1],t[2],t[3],4);
                    n=0;
                }
                break;
            case '=':
                switch (n)
                {
                    case 1: b64decode(&b,t[0],0,0,0,1);    break;
                    case 2: b64decode(&b,t[0],t[1],0,0,2); break;
                    case 3: b64decode(&b,t[0],t[1],t[2],0,3); break;
                }
            case 0:
                luaL_pushresult(&b);
                return 1;
            case '\n': case '\r': case '\t':
            case ' ': case '\f': case '\b':
                break;
        }
    }
    return 0;
}

static void tea_encrypt (uint32_t* v, uint32_t* k) {
    uint32_t v0=v[0], v1=v[1], sum=0, i;
    uint32_t delta=0x9e3779b9;
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];
    for (i=0; i < 32; i++) {
        sum += delta;
        v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        v1 += ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
    }
    v[0]=v0; v[1]=v1;
}

static void tea_decrypt (uint32_t* v, uint32_t* k) {
    uint32_t v0=v[0], v1=v[1], sum=0xC6EF3720, i;
    uint32_t delta=0x9e3779b9;
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];
    for (i=0; i<32; i++) {
        v1 -= ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
        v0 -= ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        sum -= delta;
    }
    v[0]=v0; v[1]=v1;
}

static int l_teaenc(lua_State *L) {
    size_t keylen;
    const char *teakey = luaL_checklstring(L, 2, &keylen);
    char crypt_buf[8];
    luaL_checktype(L, 1, LUA_TSTRING);
    if(lua_strlen(L, 1) == 8) {
        const char *input = lua_tostring(L, 1);
        memcpy(crypt_buf, input, 8);
    } else
        return luaL_error(L, "data must be 64bit long");
    if(keylen != 16)
        return luaL_error(L, "key must be 128bit long");
    tea_encrypt((uint32_t *)crypt_buf, (uint32_t *)teakey);
    lua_pushlstring(L, crypt_buf, 8);
    return 1;
}

static int l_teadec(lua_State *L) {
    size_t keylen;
    const char *teakey = luaL_checklstring(L, 2, &keylen);
    char crypt_buf[8];
    luaL_checktype(L, 1, LUA_TSTRING);
    if(lua_strlen(L, 1) == 8) {
        const char *input = lua_tostring(L, 1);
        memcpy(crypt_buf, input, 8);
    } else
        return luaL_error(L, "data must be 64bit long");
    if(keylen != 16)
        return luaL_error(L, "key must be 128bit long");
    tea_decrypt((uint32_t *)crypt_buf, (uint32_t *)teakey);
    lua_pushlstring(L, crypt_buf, 8);
    return 1;
}

typedef struct
{
    uint32_t state[5];
    uint32_t count[2];
    unsigned char buffer[64];
} SHA1_CTX;

#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

/* blk0() and blk() perform the initial expand. */
/* I got the idea of expanding during the round function from SSLeay */
#if BYTE_ORDER == LITTLE_ENDIAN
#define blk0(i) (block->l[i] = (rol(block->l[i],24)&0xFF00FF00) \
    |(rol(block->l[i],8)&0x00FF00FF))
#elif BYTE_ORDER == BIG_ENDIAN
#define blk0(i) block->l[i]
#else
#error "Endianness not defined!"
#endif
#define blk(i) (block->l[i&15] = rol(block->l[(i+13)&15]^block->l[(i+8)&15] \
    ^block->l[(i+2)&15]^block->l[i&15],1))

/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define R0(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk0(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R1(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R2(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0x6ED9EBA1+rol(v,5);w=rol(w,30);
#define R3(v,w,x,y,z,i) z+=(((w|x)&y)|(w&x))+blk(i)+0x8F1BBCDC+rol(v,5);w=rol(w,30);
#define R4(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0xCA62C1D6+rol(v,5);w=rol(w,30);


/* Hash a single 512-bit block. This is the core of the algorithm. */

void SHA1Transform(uint32_t state[5], const unsigned char buffer[64])
{
    uint32_t a, b, c, d, e;

    typedef union
    {
        unsigned char c[64];
        uint32_t l[16];
    } CHAR64LONG16;

    CHAR64LONG16 block[1];      /* use array to appear as a pointer */
    memcpy(block, buffer, 64);
    /* Copy context->state[] to working vars */
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    /* 4 rounds of 20 operations each. Loop unrolled. */
    R0(a, b, c, d, e, 0);
    R0(e, a, b, c, d, 1);
    R0(d, e, a, b, c, 2);
    R0(c, d, e, a, b, 3);
    R0(b, c, d, e, a, 4);
    R0(a, b, c, d, e, 5);
    R0(e, a, b, c, d, 6);
    R0(d, e, a, b, c, 7);
    R0(c, d, e, a, b, 8);
    R0(b, c, d, e, a, 9);
    R0(a, b, c, d, e, 10);
    R0(e, a, b, c, d, 11);
    R0(d, e, a, b, c, 12);
    R0(c, d, e, a, b, 13);
    R0(b, c, d, e, a, 14);
    R0(a, b, c, d, e, 15);
    R1(e, a, b, c, d, 16);
    R1(d, e, a, b, c, 17);
    R1(c, d, e, a, b, 18);
    R1(b, c, d, e, a, 19);
    R2(a, b, c, d, e, 20);
    R2(e, a, b, c, d, 21);
    R2(d, e, a, b, c, 22);
    R2(c, d, e, a, b, 23);
    R2(b, c, d, e, a, 24);
    R2(a, b, c, d, e, 25);
    R2(e, a, b, c, d, 26);
    R2(d, e, a, b, c, 27);
    R2(c, d, e, a, b, 28);
    R2(b, c, d, e, a, 29);
    R2(a, b, c, d, e, 30);
    R2(e, a, b, c, d, 31);
    R2(d, e, a, b, c, 32);
    R2(c, d, e, a, b, 33);
    R2(b, c, d, e, a, 34);
    R2(a, b, c, d, e, 35);
    R2(e, a, b, c, d, 36);
    R2(d, e, a, b, c, 37);
    R2(c, d, e, a, b, 38);
    R2(b, c, d, e, a, 39);
    R3(a, b, c, d, e, 40);
    R3(e, a, b, c, d, 41);
    R3(d, e, a, b, c, 42);
    R3(c, d, e, a, b, 43);
    R3(b, c, d, e, a, 44);
    R3(a, b, c, d, e, 45);
    R3(e, a, b, c, d, 46);
    R3(d, e, a, b, c, 47);
    R3(c, d, e, a, b, 48);
    R3(b, c, d, e, a, 49);
    R3(a, b, c, d, e, 50);
    R3(e, a, b, c, d, 51);
    R3(d, e, a, b, c, 52);
    R3(c, d, e, a, b, 53);
    R3(b, c, d, e, a, 54);
    R3(a, b, c, d, e, 55);
    R3(e, a, b, c, d, 56);
    R3(d, e, a, b, c, 57);
    R3(c, d, e, a, b, 58);
    R3(b, c, d, e, a, 59);
    R4(a, b, c, d, e, 60);
    R4(e, a, b, c, d, 61);
    R4(d, e, a, b, c, 62);
    R4(c, d, e, a, b, 63);
    R4(b, c, d, e, a, 64);
    R4(a, b, c, d, e, 65);
    R4(e, a, b, c, d, 66);
    R4(d, e, a, b, c, 67);
    R4(c, d, e, a, b, 68);
    R4(b, c, d, e, a, 69);
    R4(a, b, c, d, e, 70);
    R4(e, a, b, c, d, 71);
    R4(d, e, a, b, c, 72);
    R4(c, d, e, a, b, 73);
    R4(b, c, d, e, a, 74);
    R4(a, b, c, d, e, 75);
    R4(e, a, b, c, d, 76);
    R4(d, e, a, b, c, 77);
    R4(c, d, e, a, b, 78);
    R4(b, c, d, e, a, 79);
    /* Add the working vars back into context.state[] */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    /* Wipe variables */
    a = b = c = d = e = 0;
    memset(block, '\0', sizeof(block));
}

/* Run your data through this. */
void SHA1Update(SHA1_CTX * context, const unsigned char *data, uint32_t len)
{
    uint32_t i, j;
    j = context->count[0];
    if ((context->count[0] += len << 3) < j) context->count[1]++;
    context->count[1] += (len >> 29);
    j = (j >> 3) & 63;
    if ((j + len) > 63) {
        memcpy(&context->buffer[j], data, (i = 64 - j));
        SHA1Transform(context->state, context->buffer);
        for (; i + 63 < len; i += 64)
            SHA1Transform(context->state, &data[i]);
        j = 0;
    }
    else
        i = 0;
    memcpy(&context->buffer[j], &data[i], len - i);
}

void SHA1Final(unsigned char digest[20], SHA1_CTX * context)
{
    unsigned i;
    unsigned char finalcount[8];
    unsigned char c;

    for (i = 0; i < 8; i++)
        finalcount[i] = (unsigned char) ((context->count[(i >= 4 ? 0 : 1)] >> ((3 - (i & 3)) * 8)) & 255);
    c = 0200;
    SHA1Update(context, &c, 1);
    while ((context->count[0] & 504) != 448)
    {
        c = 0000;
        SHA1Update(context, &c, 1);
    }
    SHA1Update(context, finalcount, 8); /* Should cause a SHA1Transform() */
    for (i = 0; i < 20; i++)
        digest[i] = (unsigned char)((context->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
    /* Wipe variables */
    memset(context, '\0', sizeof(*context));
    memset(&finalcount, '\0', sizeof(finalcount));
}

static int l_sha1(lua_State *L) {
    size_t msglen;
    const char *msg = luaL_checklstring(L, 1, &msglen);
    SHA1_CTX c;
    unsigned char m[20];
    c.state[0] = 0x67452301;
    c.state[1] = 0xEFCDAB89;
    c.state[2] = 0x98BADCFE;
    c.state[3] = 0x10325476;
    c.state[4] = 0xC3D2E1F0;
    c.count[0] = c.count[1] = 0;
    SHA1Update(&c, msg, msglen);
    SHA1Final(m, &c);
    lua_pushlstring(L, m, sizeof(m));
    return 1;
}

static int l_md5(lua_State *L) {
    size_t msglen;
    const char *msg = luaL_checklstring(L, 1, &msglen);
    unsigned char m[16];
    md5(msg, msglen, m);
    lua_pushlstring(L, m, 16);
    return 1;
}

luaL_Reg lreg_codec[] = {
    { "new_rc4", l_newrc4 },
    { "teaenc", l_teaenc },
    { "teadec", l_teadec },
    { "b64encode", l_b64encode },
    { "b64decode", l_b64decode },
    { "sha1", l_sha1 },
    { "md5", l_md5 },
    { NULL, NULL }
};
