/* LuaTomCrypt -- Hash functions
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

/* register_hash(ltc_hash_descriptor) */
static int tc_register_hash(lua_State *L) {
    struct ltc_hash_descriptor **hash;

    /* Get function arguments */
    hash = (struct ltc_hash_descriptor **) luaL_checkudata(L, 1, "TomCrypt.LtcHashDescriptor");
    luaL_argcheck(L, hash != NULL, 1, "`ltc_hash_descriptor' expected");

    if (register_hash(*hash) == -1) {
        /* Push nil and error message */
        lua_pushnil(L);
        lua_pushstring(L, "register failed");
        return 2;
    }

    lua_pushboolean(L, 1);
    return 1;
}

/* register_hash(ltc_hash_descriptor) */
static int tc_unregister_hash(lua_State *L) {
    struct ltc_hash_descriptor **hash;

    /* Get function arguments */
    hash = (struct ltc_hash_descriptor **) luaL_checkudata(L, 1, "TomCrypt.LtcHashDescriptor");
    luaL_argcheck(L, hash != NULL, 1, "`ltc_hash_descriptor' expected");

    if (unregister_hash(*hash) == -1) {
        /* Push nil and error message */
        lua_pushnil(L);
        lua_pushstring(L, "unregister failed");
        return 2;
    }

    lua_pushboolean(L, 1);
    return 1;
}

/* Takes hash id as argument and returns HashState userdata */
static int tc_id_init(lua_State *L) {
    int idx;
    hash_state *md;

    /* Get function arguments */
    idx = luaL_checkint(L, 1);

    /* Create userdata and set metatable for HashState */
    md = (hash_state *) lua_newuserdata(L, sizeof(hash_state));
    luaL_getmetatable(L, "TomCrypt.HashState");
    lua_setmetatable(L, -2);

    hash_descriptor[idx].init(md);
    return 1;
}

/* Takes hash id, HashState and string as argument, returns true or nil and
 * error message.
 */
static int tc_id_process(lua_State *L) {
    const char *instring;
    int err, idx;
    hash_state *md;

    /* Get function arguments */
    idx = luaL_checkint(L, 1);

    md = (hash_state *) luaL_checkudata(L, 2, "TomCrypt.HashState");
    luaL_argcheck(L, md != NULL, 2, "`hashstate' expected");

    instring = luaL_checkstring(L, 3);

    /* Call the library function */
    err = hash_descriptor[idx].process(md, (unsigned char *) instring, strlen(instring));
    if (err != CRYPT_OK) {
        /* Push nil and error message */
        lua_pushnil(L);
        lua_pushstring(L, error_to_string(err));
        return 2;
    }

    lua_pushboolean(L, 1);
    return 1;
}

/* Takes hash id, HashState as argument, return the calculated hash or nil and
 * error message
 */
static int tc_id_done(lua_State *L) {
    unsigned char out[MAXBLOCKSIZE] = { 0 };
    int err, idx;
    hash_state *md;

    /* Get function arguments */
    idx = luaL_checkint(L, 1);

    md = (hash_state *) luaL_checkudata(L, 2, "TomCrypt.HashState");
    luaL_argcheck(L, md != NULL, 2, "`hashstate' expected");

    /* Call the library function */
    err = hash_descriptor[idx].done(md, out);
    if (err != CRYPT_OK) {
        /* Push nil and error message */
        lua_pushnil(L);
        lua_pushstring(L, error_to_string(err));
        return 2;
    }

    lua_pushstring(L, (char *) out);
    return 1;
}

/* find_hash(name) --> hash id.
 */
static int tc_find_hash(lua_State *L) {
    const char *name;
    int idx;

    /* Get function arguments */
    name = luaL_checkstring(L, 1);

    idx = find_hash(name);
    if (idx == -1) {
        /* Push nil and error message */
        lua_pushnil(L);
        lua_pushstring(L, "invalid hash name");
        return 2;
    }

    lua_pushinteger(L, idx);
    return 1;
}

static int tc_hash_string(lua_State *L) {
    int err, idx;
    const char *instring;
    unsigned char out[MAXBLOCKSIZE] = { 0 };
    unsigned long outlen;

    /* Get function arguments */
    idx = luaL_checkint(L, 1);
    instring = luaL_checkstring(L, 2);

    err = hash_memory(idx, (unsigned char *) instring, lua_strlen(L, 2), out, &outlen);
    if (err != CRYPT_OK) {
        /* Push nil and error message */
        lua_pushnil(L);
        lua_pushstring(L, error_to_string(err));
        return 2;
    }

    lua_pushstring(L, (char *) out);
    lua_pushinteger(L, outlen);
    return 2;
}

static int tc_hash_file(lua_State *L) {
    int err, idx;
    const char *fname;
    unsigned char out[MAXBLOCKSIZE] = { 0 };
    /* hash_filehandle() checks whether hashsize is smaller then outlen, so set
     * it to MAXBLOCKSIZE. This is a bug in libtomcrypt.
     */
    unsigned long outlen = MAXBLOCKSIZE;

    /* Get function arguments */
    idx = luaL_checkint(L, 1);
    fname = luaL_checkstring(L, 2);

    err = hash_file(idx, fname, out, &outlen);
    if (err != CRYPT_OK) {
        /* Push nil and error message */
        lua_pushnil(L);
        lua_pushstring(L, error_to_string(err));
        return 2;
    }

    lua_pushstring(L, (char *) out);
    lua_pushinteger(L, outlen);
    return 2;
}

static int tc_hash_filehandle(lua_State *L) {
    int err, idx;
    FILE **infp;
    unsigned char out[MAXBLOCKSIZE] = { 0 };
    unsigned long outlen = MAXBLOCKSIZE;

    /* Get function arguments */
    idx = luaL_checkint(L, 1);
    infp = (FILE **) luaL_checkudata(L, 2, LUA_FILEHANDLE);
    luaL_argcheck(L, infp != NULL, 2, "`file' expected");

    err = hash_filehandle(idx, *infp, out, &outlen);
    if (err != CRYPT_OK) {
        /* Push nil and error message */
        lua_pushnil(L);
        lua_pushstring(L, error_to_string(err));
        return 2;
    }

    lua_pushstring(L, (char *) out);
    lua_pushinteger(L, outlen);
    return 2;
}

/* HASHNAME_init() functions
 * take no argument and return HashState userdata.
 * HASHNAME_process() functions
 * take HashState and string as argument and return true or nil and error
 * message.
 * HASHNAME_done() functions
 * take HashState as argument and return the calculated hash or nil and error
 * message.
 * HASHNAME_test() functions
 * take no argument and return nil and error message or true
 */

#ifdef LTC_WHIRLPOOL
static int tc_whirlpool_init(lua_State *L) {
    hash_state *md;

    /* Create userdata and set metatable for HashState */
    md = (hash_state *) lua_newuserdata(L, sizeof(hash_state));
    luaL_getmetatable(L, "TomCrypt.HashState");
    lua_setmetatable(L, -2);

    whirlpool_init(md);
    return 1;
}

static int tc_whirlpool_process(lua_State *L) {
    const char *instring;
    int err;
    hash_state *md;

    /* Get function arguments */
    md = (hash_state *) luaL_checkudata(L, 1, "TomCrypt.HashState");
    luaL_argcheck(L, md != NULL, 1, "`hashstate' expected");

    instring = luaL_checkstring(L, 2);

    /* Call the library function */
    err = whirlpool_process(md, (unsigned char *) instring, strlen(instring));
    if (err != CRYPT_OK) {
        /* Push nil and error message */
        lua_pushnil(L);
        lua_pushstring(L, error_to_string(err));
        return 2;
    }

    lua_pushboolean(L, 1);
    return 1;
}

static int tc_whirlpool_done(lua_State *L) {
    unsigned char out[MAXBLOCKSIZE] = { 0 };
    int err;
    hash_state *md;

    /* Get function arguments */
    md = (hash_state *) luaL_checkudata(L, 1, "TomCrypt.HashState");
    luaL_argcheck(L, md != NULL, 1, "`hashstate' expected");

    /* Call the library function */
    err = whirlpool_done(md, out);
    if (err != CRYPT_OK) {
        /* Push nil and error message */
        lua_pushnil(L);
        lua_pushstring(L, error_to_string(err));
        return 2;
    }

    lua_pushstring(L, (char *) out);
    return 1;
}

static int tc_whirlpool_test(lua_State *L) {
    int err;

    err = whirlpool_test();
    if (err != CRYPT_OK) {
        /* Push nil and error message */
        lua_pushnil(L);
        lua_pushstring(L, error_to_string(err));
        return 2;
    }

    lua_pushboolean(L, 1);
    return 1;
}
#endif /* LTC_WHIRLPOOL */

#ifdef LTC_SHA512
static int tc_sha512_init(lua_State *L) {
    hash_state *md;

    /* Create userdata and set metatable for HashState */
    md = (hash_state *) lua_newuserdata(L, sizeof(hash_state));
    luaL_getmetatable(L, "TomCrypt.HashState");
    lua_setmetatable(L, -2);

    sha512_init(md);
    return 1;
}

static int tc_sha512_process(lua_State *L) {
    const char *instring;
    int err;
    hash_state *md;

    /* Get function arguments */
    md = (hash_state *) luaL_checkudata(L, 1, "TomCrypt.HashState");
    luaL_argcheck(L, md != NULL, 1, "`hashstate' expected");

    instring = luaL_checkstring(L, 2);

    /* Call the library function */
    err = sha512_process(md, (unsigned char *) instring, strlen(instring));
    if (err != CRYPT_OK) {
        /* Push nil and error message */
        lua_pushnil(L);
        lua_pushstring(L, error_to_string(err));
        return 2;
    }

    lua_pushboolean(L, 1);
    return 1;
}

static int tc_sha512_done(lua_State *L) {
    unsigned char out[MAXBLOCKSIZE] = { 0 };
    int err;
    hash_state *md;

    /* Get function arguments */
    md = (hash_state *) luaL_checkudata(L, 1, "TomCrypt.HashState");
    luaL_argcheck(L, md != NULL, 1, "`hashstate' expected");

    /* Call the library function */
    err = sha512_done(md, out);
    if (err != CRYPT_OK) {
        /* Push nil and error message */
        lua_pushnil(L);
        lua_pushstring(L, error_to_string(err));
        return 2;
    }

    lua_pushstring(L, (char *) out);
    return 1;
}

static int tc_sha512_test(lua_State *L) {
    int err;

    err = sha512_test();
    if (err != CRYPT_OK) {
        /* Push nil and error message */
        lua_pushnil(L);
        lua_pushstring(L, error_to_string(err));
        return 2;
    }

    lua_pushboolean(L, 1);
    return 1;
}
#endif /* LTC_SHA512 */

#ifdef LTC_SHA384
static int tc_sha384_init(lua_State *L) {
    hash_state *md;

    /* Create userdata and set metatable for HashState */
    md = (hash_state *) lua_newuserdata(L, sizeof(hash_state));
    luaL_getmetatable(L, "TomCrypt.HashState");
    lua_setmetatable(L, -2);

    sha384_init(md);
    return 1;
}

static int tc_sha384_process(lua_State *L) {
    const char *instring;
    int err;
    hash_state *md;

    /* Get function arguments */
    md = (hash_state *) luaL_checkudata(L, 1, "TomCrypt.HashState");
    luaL_argcheck(L, md != NULL, 1, "`hashstate' expected");

    instring = luaL_checkstring(L, 2);

    /* Call the library function */
    err = sha384_process(md, (unsigned char *) instring, strlen(instring));
    if (err != CRYPT_OK) {
        /* Push nil and error message */
        lua_pushnil(L);
        lua_pushstring(L, error_to_string(err));
        return 2;
    }

    lua_pushboolean(L, 1);
    return 1;
}

static int tc_sha384_done(lua_State *L) {
    unsigned char out[MAXBLOCKSIZE] = { 0 };
    int err;
    hash_state *md;

    /* Get function arguments */
    md = (hash_state *) luaL_checkudata(L, 1, "TomCrypt.HashState");
    luaL_argcheck(L, md != NULL, 1, "`hashstate' expected");

    /* Call the library function */
    err = sha384_done(md, out);
    if (err != CRYPT_OK) {
        /* Push nil and error message */
        lua_pushnil(L);
        lua_pushstring(L, error_to_string(err));
        return 2;
    }

    lua_pushstring(L, (char *) out);
    return 1;
}

static int tc_sha384_test(lua_State *L) {
    int err;

    err = sha384_test();
    if (err != CRYPT_OK) {
        /* Push nil and error message */
        lua_pushnil(L);
        lua_pushstring(L, error_to_string(err));
        return 2;
    }

    lua_pushboolean(L, 1);
    return 1;
}
#endif /* LTC_SHA384 */

#ifdef LTC_SHA256
static int tc_sha256_init(lua_State *L) {
    hash_state *md;

    /* Create userdata and set metatable for HashState */
    md = (hash_state *) lua_newuserdata(L, sizeof(hash_state));
    luaL_getmetatable(L, "TomCrypt.HashState");
    lua_setmetatable(L, -2);

    sha256_init(md);
    return 1;
}

static int tc_sha256_process(lua_State *L) {
    const char *instring;
    int err;
    hash_state *md;

    /* Get function arguments */
    md = (hash_state *) luaL_checkudata(L, 1, "TomCrypt.HashState");
    luaL_argcheck(L, md != NULL, 1, "`hashstate' expected");

    instring = luaL_checkstring(L, 2);

    /* Call the library function */
    err = sha256_process(md, (unsigned char *) instring, strlen(instring));
    if (err != CRYPT_OK) {
        /* Push nil and error message */
        lua_pushnil(L);
        lua_pushstring(L, error_to_string(err));
        return 2;
    }

    lua_pushboolean(L, 1);
    return 1;
}

static int tc_sha256_done(lua_State *L) {
    unsigned char out[MAXBLOCKSIZE] = { 0 };
    int err;
    hash_state *md;

    /* Get function arguments */
    md = (hash_state *) luaL_checkudata(L, 1, "TomCrypt.HashState");
    luaL_argcheck(L, md != NULL, 1, "`hashstate' expected");

    /* Call the library function */
    err = sha256_done(md, out);
    if (err != CRYPT_OK) {
        /* Push nil and error message */
        lua_pushnil(L);
        lua_pushstring(L, error_to_string(err));
        return 2;
    }

    lua_pushstring(L, (char *) out);
    return 1;
}

static int tc_sha256_test(lua_State *L) {
    int err;

    err = sha256_test();
    if (err != CRYPT_OK) {
        /* Push nil and error message */
        lua_pushnil(L);
        lua_pushstring(L, error_to_string(err));
        return 2;
    }

    lua_pushboolean(L, 1);
    return 1;
}
#endif /* LTC_SHA256 */

#ifdef LTC_SHA224
static int tc_sha224_init(lua_State *L) {
    hash_state *md;

    /* Create userdata and set metatable for HashState */
    md = (hash_state *) lua_newuserdata(L, sizeof(hash_state));
    luaL_getmetatable(L, "TomCrypt.HashState");
    lua_setmetatable(L, -2);

    sha224_init(md);
    return 1;
}

static int tc_sha224_process(lua_State *L) {
    const char *instring;
    int err;
    hash_state *md;

    /* Get function arguments */
    md = (hash_state *) luaL_checkudata(L, 1, "TomCrypt.HashState");
    luaL_argcheck(L, md != NULL, 1, "`hashstate' expected");

    instring = luaL_checkstring(L, 2);

    /* Call the library function */
    err = sha224_process(md, (unsigned char *) instring, strlen(instring));
    if (err != CRYPT_OK) {
        /* Push nil and error message */
        lua_pushnil(L);
        lua_pushstring(L, error_to_string(err));
        return 2;
    }

    lua_pushboolean(L, 1);
    return 1;
}

static int tc_sha224_done(lua_State *L) {
    unsigned char out[MAXBLOCKSIZE] = { 0 };
    int err;
    hash_state *md;

    /* Get function arguments */
    md = (hash_state *) luaL_checkudata(L, 1, "TomCrypt.HashState");
    luaL_argcheck(L, md != NULL, 1, "`hashstate' expected");

    /* Call the library function */
    err = sha224_done(md, out);
    if (err != CRYPT_OK) {
        /* Push nil and error message */
        lua_pushnil(L);
        lua_pushstring(L, error_to_string(err));
        return 2;
    }

    lua_pushstring(L, (char *) out);
    return 1;
}

static int tc_sha224_test(lua_State *L) {
    int err;

    err = sha224_test();
    if (err != CRYPT_OK) {
        /* Push nil and error message */
        lua_pushnil(L);
        lua_pushstring(L, error_to_string(err));
        return 2;
    }

    lua_pushboolean(L, 1);
    return 1;
}
#endif /* LTC_SHA224 */

#ifdef LTC_SHA1
static int tc_sha1_init(lua_State *L) {
    hash_state *md;

    /* Create userdata and set metatable for HashState */
    md = (hash_state *) lua_newuserdata(L, sizeof(hash_state));
    luaL_getmetatable(L, "TomCrypt.HashState");
    lua_setmetatable(L, -2);

    sha1_init(md);
    return 1;
}

static int tc_sha1_process(lua_State *L) {
    const char *instring;
    int err;
    hash_state *md;

    /* Get function arguments */
    md = (hash_state *) luaL_checkudata(L, 1, "TomCrypt.HashState");
    luaL_argcheck(L, md != NULL, 1, "`hashstate' expected");

    instring = luaL_checkstring(L, 2);

    /* Call the library function */
    err = sha1_process(md, (unsigned char *) instring, strlen(instring));
    if (err != CRYPT_OK) {
        /* Push nil and error message */
        lua_pushnil(L);
        lua_pushstring(L, error_to_string(err));
        return 2;
    }

    lua_pushboolean(L, 1);
    return 1;
}

static int tc_sha1_done(lua_State *L) {
    unsigned char out[MAXBLOCKSIZE] = { 0 };
    int err;
    hash_state *md;

    /* Get function arguments */
    md = (hash_state *) luaL_checkudata(L, 1, "TomCrypt.HashState");
    luaL_argcheck(L, md != NULL, 1, "`hashstate' expected");

    /* Call the library function */
    err = sha1_done(md, out);
    if (err != CRYPT_OK) {
        /* Push nil and error message */
        lua_pushnil(L);
        lua_pushstring(L, error_to_string(err));
        return 2;
    }

    lua_pushstring(L, (char *) out);
    return 1;
}

static int tc_sha1_test(lua_State *L) {
    int err;

    err = sha1_test();
    if (err != CRYPT_OK) {
        /* Push nil and error message */
        lua_pushnil(L);
        lua_pushstring(L, error_to_string(err));
        return 2;
    }

    lua_pushboolean(L, 1);
    return 1;
}
#endif /* LTC_SHA1 */

#ifdef LTC_MD5
static int tc_md5_init(lua_State *L) {
    hash_state *md;

    /* Create userdata and set metatable for HashState */
    md = (hash_state *) lua_newuserdata(L, sizeof(hash_state));
    luaL_getmetatable(L, "TomCrypt.HashState");
    lua_setmetatable(L, -2);

    md5_init(md);
    return 1;
}

static int tc_md5_process(lua_State *L) {
    const char *instring;
    int err;
    hash_state *md;

    /* Get function arguments */
    md = (hash_state *) luaL_checkudata(L, 1, "TomCrypt.HashState");
    luaL_argcheck(L, md != NULL, 1, "`hashstate' expected");

    instring = luaL_checkstring(L, 2);

    /* Call the library function */
    err = md5_process(md, (unsigned char *) instring, strlen(instring));
    if (err != CRYPT_OK) {
        /* Push nil and error message */
        lua_pushnil(L);
        lua_pushstring(L, error_to_string(err));
        return 2;
    }

    lua_pushboolean(L, 1);
    return 1;
}

static int tc_md5_done(lua_State *L) {
    unsigned char out[MAXBLOCKSIZE] = { 0 };
    int err;
    hash_state *md;

    /* Get function arguments */
    md = (hash_state *) luaL_checkudata(L, 1, "TomCrypt.HashState");
    luaL_argcheck(L, md != NULL, 1, "`hashstate' expected");

    /* Call the library function */
    err = md5_done(md, out);
    if (err != CRYPT_OK) {
        /* Push nil and error message */
        lua_pushnil(L);
        lua_pushstring(L, error_to_string(err));
        return 2;
    }

    lua_pushstring(L, (char *) out);
    return 1;
}

static int tc_md5_test(lua_State *L) {
    int err;

    err = md5_test();
    if (err != CRYPT_OK) {
        /* Push nil and error message */
        lua_pushnil(L);
        lua_pushstring(L, error_to_string(err));
        return 2;
    }

    lua_pushboolean(L, 1);
    return 1;
}
#endif /* LTC_MD5 */

#ifdef LTC_MD4
static int tc_md4_init(lua_State *L) {
    hash_state *md;

    /* Create userdata and set metatable for HashState */
    md = (hash_state *) lua_newuserdata(L, sizeof(hash_state));
    luaL_getmetatable(L, "TomCrypt.HashState");
    lua_setmetatable(L, -2);

    md4_init(md);
    return 1;
}

static int tc_md4_process(lua_State *L) {
    const char *instring;
    int err;
    hash_state *md;

    /* Get function arguments */
    md = (hash_state *) luaL_checkudata(L, 1, "TomCrypt.HashState");
    luaL_argcheck(L, md != NULL, 1, "`hashstate' expected");

    instring = luaL_checkstring(L, 2);

    /* Call the library function */
    err = md4_process(md, (unsigned char *) instring, strlen(instring));
    if (err != CRYPT_OK) {
        /* Push nil and error message */
        lua_pushnil(L);
        lua_pushstring(L, error_to_string(err));
        return 2;
    }

    lua_pushboolean(L, 1);
    return 1;
}

static int tc_md4_done(lua_State *L) {
    unsigned char out[MAXBLOCKSIZE] = { 0 };
    int err;
    hash_state *md;

    /* Get function arguments */
    md = (hash_state *) luaL_checkudata(L, 1, "TomCrypt.HashState");
    luaL_argcheck(L, md != NULL, 1, "`hashstate' expected");

    /* Call the library function */
    err = md4_done(md, out);
    if (err != CRYPT_OK) {
        /* Push nil and error message */
        lua_pushnil(L);
        lua_pushstring(L, error_to_string(err));
        return 2;
    }

    lua_pushstring(L, (char *) out);
    return 1;
}

static int tc_md4_test(lua_State *L) {
    int err;

    err = md4_test();
    if (err != CRYPT_OK) {
        /* Push nil and error message */
        lua_pushnil(L);
        lua_pushstring(L, error_to_string(err));
        return 2;
    }

    lua_pushboolean(L, 1);
    return 1;
}
#endif /* LTC_MD4 */

#ifdef LTC_MD2
static int tc_md2_init(lua_State *L) {
    hash_state *md;

    /* Create userdata and set metatable for HashState */
    md = (hash_state *) lua_newuserdata(L, sizeof(hash_state));
    luaL_getmetatable(L, "TomCrypt.HashState");
    lua_setmetatable(L, -2);

    md2_init(md);
    return 1;
}

static int tc_md2_process(lua_State *L) {
    const char *instring;
    int err;
    hash_state *md;

    /* Get function arguments */
    md = (hash_state *) luaL_checkudata(L, 1, "TomCrypt.HashState");
    luaL_argcheck(L, md != NULL, 1, "`hashstate' expected");

    instring = luaL_checkstring(L, 2);

    /* Call the library function */
    err = md2_process(md, (unsigned char *) instring, strlen(instring));
    if (err != CRYPT_OK) {
        /* Push nil and error message */
        lua_pushnil(L);
        lua_pushstring(L, error_to_string(err));
        return 2;
    }

    lua_pushboolean(L, 1);
    return 1;
}

static int tc_md2_done(lua_State *L) {
    unsigned char out[MAXBLOCKSIZE] = { 0 };
    int err;
    hash_state *md;

    /* Get function arguments */
    md = (hash_state *) luaL_checkudata(L, 1, "TomCrypt.HashState");
    luaL_argcheck(L, md != NULL, 1, "`hashstate' expected");

    /* Call the library function */
    err = md2_done(md, out);
    if (err != CRYPT_OK) {
        /* Push nil and error message */
        lua_pushnil(L);
        lua_pushstring(L, error_to_string(err));
        return 2;
    }

    lua_pushstring(L, (char *) out);
    return 1;
}

static int tc_md2_test(lua_State *L) {
    int err;

    err = md2_test();
    if (err != CRYPT_OK) {
        /* Push nil and error message */
        lua_pushnil(L);
        lua_pushstring(L, error_to_string(err));
        return 2;
    }

    lua_pushboolean(L, 1);
    return 1;
}
#endif /* LTC_MD2 */

#ifdef LTC_TIGER
static int tc_tiger_init(lua_State *L) {
    hash_state *md;

    /* Create userdata and set metatable for HashState */
    md = (hash_state *) lua_newuserdata(L, sizeof(hash_state));
    luaL_getmetatable(L, "TomCrypt.HashState");
    lua_setmetatable(L, -2);

    tiger_init(md);
    return 1;
}

static int tc_tiger_process(lua_State *L) {
    const char *instring;
    int err;
    hash_state *md;

    /* Get function arguments */
    md = (hash_state *) luaL_checkudata(L, 1, "TomCrypt.HashState");
    luaL_argcheck(L, md != NULL, 1, "`hashstate' expected");

    instring = luaL_checkstring(L, 2);

    /* Call the library function */
    err = tiger_process(md, (unsigned char *) instring, strlen(instring));
    if (err != CRYPT_OK) {
        /* Push nil and error message */
        lua_pushnil(L);
        lua_pushstring(L, error_to_string(err));
        return 2;
    }

    lua_pushboolean(L, 1);
    return 1;
}

static int tc_tiger_done(lua_State *L) {
    unsigned char out[MAXBLOCKSIZE] = { 0 };
    int err;
    hash_state *md;

    /* Get function arguments */
    md = (hash_state *) luaL_checkudata(L, 1, "TomCrypt.HashState");
    luaL_argcheck(L, md != NULL, 1, "`hashstate' expected");

    /* Call the library function */
    err = tiger_done(md, out);
    if (err != CRYPT_OK) {
        /* Push nil and error message */
        lua_pushnil(L);
        lua_pushstring(L, error_to_string(err));
        return 2;
    }

    lua_pushstring(L, (char *) out);
    return 1;
}

static int tc_tiger_test(lua_State *L) {
    int err;

    err = tiger_test();
    if (err != CRYPT_OK) {
        /* Push nil and error message */
        lua_pushnil(L);
        lua_pushstring(L, error_to_string(err));
        return 2;
    }

    lua_pushboolean(L, 1);
    return 1;
}
#endif /* LTC_TIGER */

#ifdef LTC_RIPEMD128
static int tc_rmd128_init(lua_State *L) {
    hash_state *md;

    /* Create userdata and set metatable for HashState */
    md = (hash_state *) lua_newuserdata(L, sizeof(hash_state));
    luaL_getmetatable(L, "TomCrypt.HashState");
    lua_setmetatable(L, -2);

    rmd128_init(md);
    return 1;
}

static int tc_rmd128_process(lua_State *L) {
    const char *instring;
    int err;
    hash_state *md;

    /* Get function arguments */
    md = (hash_state *) luaL_checkudata(L, 1, "TomCrypt.HashState");
    luaL_argcheck(L, md != NULL, 1, "`hashstate' expected");

    instring = luaL_checkstring(L, 2);

    /* Call the library function */
    err = rmd128_process(md, (unsigned char *) instring, strlen(instring));
    if (err != CRYPT_OK) {
        /* Push nil and error message */
        lua_pushnil(L);
        lua_pushstring(L, error_to_string(err));
        return 2;
    }

    lua_pushboolean(L, 1);
    return 1;
}

static int tc_rmd128_done(lua_State *L) {
    unsigned char out[MAXBLOCKSIZE] = { 0 };
    int err;
    hash_state *md;

    /* Get function arguments */
    md = (hash_state *) luaL_checkudata(L, 1, "TomCrypt.HashState");
    luaL_argcheck(L, md != NULL, 1, "`hashstate' expected");

    /* Call the library function */
    err = rmd128_done(md, out);
    if (err != CRYPT_OK) {
        /* Push nil and error message */
        lua_pushnil(L);
        lua_pushstring(L, error_to_string(err));
        return 2;
    }

    lua_pushstring(L, (char *) out);
    return 1;
}

static int tc_rmd128_test(lua_State *L) {
    int err;

    err = rmd128_test();
    if (err != CRYPT_OK) {
        /* Push nil and error message */
        lua_pushnil(L);
        lua_pushstring(L, error_to_string(err));
        return 2;
    }

    lua_pushboolean(L, 1);
    return 1;
}
#endif /* LTC_RIPEMD128 */

#ifdef LTC_RIPEMD160
static int tc_rmd160_init(lua_State *L) {
    hash_state *md;

    /* Create userdata and set metatable for HashState */
    md = (hash_state *) lua_newuserdata(L, sizeof(hash_state));
    luaL_getmetatable(L, "TomCrypt.HashState");
    lua_setmetatable(L, -2);

    rmd160_init(md);
    return 1;
}

static int tc_rmd160_process(lua_State *L) {
    const char *instring;
    int err;
    hash_state *md;

    /* Get function arguments */
    md = (hash_state *) luaL_checkudata(L, 1, "TomCrypt.HashState");
    luaL_argcheck(L, md != NULL, 1, "`hashstate' expected");

    instring = luaL_checkstring(L, 2);

    /* Call the library function */
    err = rmd160_process(md, (unsigned char *) instring, strlen(instring));
    if (err != CRYPT_OK) {
        /* Push nil and error message */
        lua_pushnil(L);
        lua_pushstring(L, error_to_string(err));
        return 2;
    }

    lua_pushboolean(L, 1);
    return 1;
}

static int tc_rmd160_done(lua_State *L) {
    unsigned char out[MAXBLOCKSIZE] = { 0 };
    int err;
    hash_state *md;

    /* Get function arguments */
    md = (hash_state *) luaL_checkudata(L, 1, "TomCrypt.HashState");
    luaL_argcheck(L, md != NULL, 1, "`hashstate' expected");

    /* Call the library function */
    err = rmd160_done(md, out);
    if (err != CRYPT_OK) {
        /* Push nil and error message */
        lua_pushnil(L);
        lua_pushstring(L, error_to_string(err));
        return 2;
    }

    lua_pushstring(L, (char *) out);
    return 1;
}

static int tc_rmd160_test(lua_State *L) {
    int err;

    err = rmd160_test();
    if (err != CRYPT_OK) {
        /* Push nil and error message */
        lua_pushnil(L);
        lua_pushstring(L, error_to_string(err));
        return 2;
    }

    lua_pushboolean(L, 1);
    return 1;
}
#endif /* LTC_RIPEMD160 */

#ifdef LTC_RIPEMD256
static int tc_rmd256_init(lua_State *L) {
    hash_state *md;

    /* Create userdata and set metatable for HashState */
    md = (hash_state *) lua_newuserdata(L, sizeof(hash_state));
    luaL_getmetatable(L, "TomCrypt.HashState");
    lua_setmetatable(L, -2);

    rmd256_init(md);
    return 1;
}

static int tc_rmd256_process(lua_State *L) {
    const char *instring;
    int err;
    hash_state *md;

    /* Get function arguments */
    md = (hash_state *) luaL_checkudata(L, 1, "TomCrypt.HashState");
    luaL_argcheck(L, md != NULL, 1, "`hashstate' expected");

    instring = luaL_checkstring(L, 2);

    /* Call the library function */
    err = rmd256_process(md, (unsigned char *) instring, strlen(instring));
    if (err != CRYPT_OK) {
        /* Push nil and error message */
        lua_pushnil(L);
        lua_pushstring(L, error_to_string(err));
        return 2;
    }

    lua_pushboolean(L, 1);
    return 1;
}

static int tc_rmd256_done(lua_State *L) {
    unsigned char out[MAXBLOCKSIZE] = { 0 };
    int err;
    hash_state *md;

    /* Get function arguments */
    md = (hash_state *) luaL_checkudata(L, 1, "TomCrypt.HashState");
    luaL_argcheck(L, md != NULL, 1, "`hashstate' expected");

    /* Call the library function */
    err = rmd256_done(md, out);
    if (err != CRYPT_OK) {
        /* Push nil and error message */
        lua_pushnil(L);
        lua_pushstring(L, error_to_string(err));
        return 2;
    }

    lua_pushstring(L, (char *) out);
    return 1;
}

static int tc_rmd256_test(lua_State *L) {
    int err;

    err = rmd256_test();
    if (err != CRYPT_OK) {
        /* Push nil and error message */
        lua_pushnil(L);
        lua_pushstring(L, error_to_string(err));
        return 2;
    }

    lua_pushboolean(L, 1);
    return 1;
}
#endif /* LTC_RIPEMD256 */

#ifdef LTC_RIPEMD320
static int tc_rmd320_init(lua_State *L) {
    hash_state *md;

    /* Create userdata and set metatable for hash_state */
    md = (hash_state *) lua_newuserdata(L, sizeof(hash_state));
    luaL_getmetatable(L, "TomCrypt.HashState");
    lua_setmetatable(L, -2);

    rmd320_init(md);
    return 1;
}

static int tc_rmd320_process(lua_State *L) {
    const char *instring;
    int err;
    hash_state *md;

    /* Get function arguments */
    md = (hash_state *) luaL_checkudata(L, 1, "TomCrypt.HashState");
    luaL_argcheck(L, md != NULL, 1, "`hashstate' expected");

    instring = luaL_checkstring(L, 2);

    /* Call the library function */
    err = rmd320_process(md, (unsigned char *) instring, strlen(instring));
    if (err != CRYPT_OK) {
        /* Push nil and error message */
        lua_pushnil(L);
        lua_pushstring(L, error_to_string(err));
        return 2;
    }

    lua_pushboolean(L, 1);
    return 1;
}

static int tc_rmd320_done(lua_State *L) {
    unsigned char out[MAXBLOCKSIZE] = { 0 };
    int err;
    hash_state *md;

    /* Get function arguments */
    md = (hash_state *) luaL_checkudata(L, 1, "TomCrypt.HashState");
    luaL_argcheck(L, md != NULL, 1, "`hashstate' expected");

    /* Call the library function */
    err = rmd320_done(md, out);
    if (err != CRYPT_OK) {
        /* Push nil and error message */
        lua_pushnil(L);
        lua_pushstring(L, error_to_string(err));
        return 2;
    }

    lua_pushstring(L, (char *) out);
    return 1;
}

static int tc_rmd320_test(lua_State *L) {
    int err;

    err = rmd320_test();
    if (err != CRYPT_OK) {
        /* Push nil and error message */
        lua_pushnil(L);
        lua_pushstring(L, error_to_string(err));
        return 2;
    }

    lua_pushboolean(L, 1);
    return 1;
}
#endif /* LTC_RIPEMD320 */

