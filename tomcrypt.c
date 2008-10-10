/* LuaTomCrypt -- Lua bindings for libtomcrypt
 * vim: set et ts=4 sts=4 sw=4 fdm=syntax :

 * Copyright 2008 Ali Polatel <polatel@itu.edu.tr>

 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:

 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.

 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
*/

#include <tomcrypt.h>

#include <lua.h>
#include <lauxlib.h>

#define MODULE_NAME "tc"
#define VERSION "0.01"

#include "tomcrypt_hash.c"

static const luaL_reg R[] = {
    /* Hash functions */
    {"find_hash",           tc_find_hash},
    {"register_hash",       tc_register_hash},
    {"unregister_hash",     tc_unregister_hash},
    {"id_init",             tc_id_init},
    {"id_process",          tc_id_process},
    {"id_done",             tc_id_done},
    {"hash_string",         tc_hash_string},
    {"hash_file",           tc_hash_file},

#ifdef LTC_WHIRLPOOL
    {"whirlpool_init",      tc_whirlpool_init},
    {"whirlpool_process",   tc_whirlpool_process},
    {"whirlpool_done",      tc_whirlpool_done},
    {"whirlpool_test",      tc_whirlpool_test},
#endif

#ifdef LTC_SHA512
    {"sha512_init",         tc_sha512_init},
    {"sha512_process",      tc_sha512_process},
    {"sha512_done",         tc_sha512_done},
    {"sha512_test",         tc_sha512_test},
#endif

#ifdef LTC_SHA384
    {"sha384_init",         tc_sha384_init},
    {"sha384_process",      tc_sha384_process},
    {"sha384_done",         tc_sha384_done},
    {"sha384_test",         tc_sha384_test},
#endif

#ifdef LTC_SHA256
    {"sha256_init",         tc_sha256_init},
    {"sha256_process",      tc_sha256_process},
    {"sha256_done",         tc_sha256_done},
    {"sha256_test",         tc_sha256_test},
#endif

#ifdef LTC_SHA224
    {"sha224_init",         tc_sha224_init},
    {"sha224_process",      tc_sha224_process},
    {"sha224_done",         tc_sha224_done},
    {"sha224_test",         tc_sha224_test},
#endif

#ifdef LTC_SHA1
    {"sha1_init",           tc_sha1_init},
    {"sha1_process",        tc_sha1_process},
    {"sha1_done",           tc_sha1_done},
    {"sha1_test",           tc_sha1_test},
#endif

#ifdef LTC_MD5
    {"md5_init",            tc_md5_init},
    {"md5_process",         tc_md5_process},
    {"md5_done",            tc_md5_done},
    {"md5_test",            tc_md5_test},
#endif

#ifdef LTC_MD4
    {"md4_init",            tc_md4_init},
    {"md4_process",         tc_md4_process},
    {"md4_done",            tc_md4_done},
    {"md4_test",            tc_md4_test},
#endif

#ifdef LTC_MD2
    {"md2_init",            tc_md2_init},
    {"md2_process",         tc_md2_process},
    {"md2_done",            tc_md2_done},
    {"md2_test",            tc_md2_test},
#endif

#ifdef LTC_TIGER
    {"tiger_init",          tc_tiger_init},
    {"tiger_process",       tc_tiger_process},
    {"tiger_done",          tc_tiger_done},
    {"tiger_test",          tc_tiger_test},
#endif

#ifdef LTC_RIPEMD128
    {"rmd128_init",         tc_rmd128_init},
    {"rmd128_process",      tc_rmd128_process},
    {"rmd128_done",         tc_rmd128_done},
    {"rmd128_test",         tc_rmd128_test},
#endif

#ifdef LTC_RIPEMD160
    {"rmd160_init",         tc_rmd160_init},
    {"rmd160_process",      tc_rmd160_process},
    {"rmd160_done",         tc_rmd160_done},
    {"rmd160_test",         tc_rmd160_test},
#endif

#ifdef LTC_RIPEMD256
    {"rmd256_init",         tc_rmd256_init},
    {"rmd256_process",      tc_rmd256_process},
    {"rmd256_done",         tc_rmd256_done},
    {"rmd160_test",         tc_rmd256_test},
#endif

#ifdef LTC_RIPEMD320
    {"rmd320_init",         tc_rmd320_init},
    {"rmd320_process",      tc_rmd320_process},
    {"rmd320_done",         tc_rmd320_done},
    {"rmd320_test",         tc_rmd320_test},
#endif

    {NULL,              NULL}
};
LUALIB_API int luaopen_tc(lua_State *L) {
    /* Metatables */
    luaL_newmetatable(L, "TomCrypt.HashState");
    luaL_newmetatable(L, "TomCrypt.LtcHashDescriptor");

    luaL_openlib(L, MODULE_NAME, R, 0);

    lua_pushliteral(L, "_VERSION");
    lua_pushstring(L, VERSION);
    lua_settable(L, -3);

    /* Make hash descriptors module variables. */
    LtcHashDescriptor *tc_hash;
#ifdef LTC_WHIRLPOOL
    lua_pushliteral(L, "whirlpool_desc");

    tc_hash = (LtcHashDescriptor *) lua_newuserdata(L, sizeof(LtcHashDescriptor));
    luaL_getmetatable(L, "TomCrypt.LtcHashDescriptor");
    lua_setmetatable(L, -2);

    tc_hash->hash = &whirlpool_desc;

    lua_settable(L, -3);
#endif

#ifdef LTC_SHA512
    lua_pushliteral(L, "sha512_desc");

    tc_hash = (LtcHashDescriptor *) lua_newuserdata(L, sizeof(LtcHashDescriptor));
    luaL_getmetatable(L, "TomCrypt.LtcHashDescriptor");
    lua_setmetatable(L, -2);

    tc_hash->hash = &sha512_desc;

    lua_settable(L, -3);
#endif

#ifdef LTC_SHA384
    lua_pushliteral(L, "sha384_desc");

    tc_hash = (LtcHashDescriptor *) lua_newuserdata(L, sizeof(LtcHashDescriptor));
    luaL_getmetatable(L, "TomCrypt.LtcHashDescriptor");
    lua_setmetatable(L, -2);

    tc_hash->hash = &sha384_desc;

    lua_settable(L, -3);
#endif

#ifdef LTC_SHA256
    lua_pushliteral(L, "sha256_desc");

    tc_hash = (LtcHashDescriptor *) lua_newuserdata(L, sizeof(LtcHashDescriptor));
    luaL_getmetatable(L, "TomCrypt.LtcHashDescriptor");
    lua_setmetatable(L, -2);

    tc_hash->hash = &sha256_desc;

    lua_settable(L, -3);
#endif

#ifdef LTC_SHA224
    lua_pushliteral(L, "sha224_desc");

    tc_hash = (LtcHashDescriptor *) lua_newuserdata(L, sizeof(LtcHashDescriptor));
    luaL_getmetatable(L, "TomCrypt.LtcHashDescriptor");
    lua_setmetatable(L, -2);

    tc_hash->hash = &sha224_desc;

    lua_settable(L, -3);
#endif

#ifdef LTC_SHA1
    lua_pushliteral(L, "sha1_desc");

    tc_hash = (LtcHashDescriptor *) lua_newuserdata(L, sizeof(LtcHashDescriptor));
    luaL_getmetatable(L, "TomCrypt.LtcHashDescriptor");
    lua_setmetatable(L, -2);

    tc_hash->hash = &sha1_desc;

    lua_settable(L, -3);
#endif

#ifdef LTC_MD5
    lua_pushliteral(L, "md5_desc");

    tc_hash = (LtcHashDescriptor *) lua_newuserdata(L, sizeof(LtcHashDescriptor));
    luaL_getmetatable(L, "TomCrypt.LtcHashDescriptor");
    lua_setmetatable(L, -2);

    tc_hash->hash = &md5_desc;

    lua_settable(L, -3);
#endif

#ifdef LTC_MD4
    lua_pushliteral(L, "md4_desc");

    tc_hash = (LtcHashDescriptor *) lua_newuserdata(L, sizeof(LtcHashDescriptor));
    luaL_getmetatable(L, "TomCrypt.LtcHashDescriptor");
    lua_setmetatable(L, -2);

    tc_hash->hash = &md4_desc;

    lua_settable(L, -3);
#endif

#ifdef LTC_MD2
    lua_pushliteral(L, "md2_desc");

    tc_hash = (LtcHashDescriptor *) lua_newuserdata(L, sizeof(LtcHashDescriptor));
    luaL_getmetatable(L, "TomCrypt.LtcHashDescriptor");
    lua_setmetatable(L, -2);

    tc_hash->hash = &md2_desc;

    lua_settable(L, -3);
#endif

#ifdef LTC_TIGER
    lua_pushliteral(L, "tiger_desc");

    tc_hash = (LtcHashDescriptor *) lua_newuserdata(L, sizeof(LtcHashDescriptor));
    luaL_getmetatable(L, "TomCrypt.LtcHashDescriptor");
    lua_setmetatable(L, -2);

    tc_hash->hash = &tiger_desc;

    lua_settable(L, -3);
#endif

#ifdef LTC_RIPEMD128
    lua_pushliteral(L, "rmd128_desc");

    tc_hash = (LtcHashDescriptor *) lua_newuserdata(L, sizeof(LtcHashDescriptor));
    luaL_getmetatable(L, "TomCrypt.LtcHashDescriptor");
    lua_setmetatable(L, -2);

    tc_hash->hash = &rmd128_desc;

    lua_settable(L, -3);
#endif

#ifdef LTC_RIPEMD160
    lua_pushliteral(L, "rmd160_desc");

    tc_hash = (LtcHashDescriptor *) lua_newuserdata(L, sizeof(LtcHashDescriptor));
    luaL_getmetatable(L, "TomCrypt.LtcHashDescriptor");
    lua_setmetatable(L, -2);

    tc_hash->hash = &rmd160_desc;

    lua_settable(L, -3);
#endif

#ifdef LTC_RIPEMD256
    lua_pushliteral(L, "rmd256_desc");

    tc_hash = (LtcHashDescriptor *) lua_newuserdata(L, sizeof(LtcHashDescriptor));
    luaL_getmetatable(L, "TomCrypt.LtcHashDescriptor");
    lua_setmetatable(L, -2);

    tc_hash->hash = &rmd256_desc;

    lua_settable(L, -3);
#endif

#ifdef LTC_RIPEMD320
    lua_pushliteral(L, "rmd320_desc");

    tc_hash = (LtcHashDescriptor *) lua_newuserdata(L, sizeof(LtcHashDescriptor));
    luaL_getmetatable(L, "TomCrypt.LtcHashDescriptor");
    lua_setmetatable(L, -2);

    tc_hash->hash = &rmd320_desc;

    lua_settable(L, -3);
#endif

    return 1;
}

