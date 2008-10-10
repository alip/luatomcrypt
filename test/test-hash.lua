#!/usr/bin/env lua
-- LuaTomCrypt tests for hash functions.
-- vim: set ft=lua et sts=4 sw=4 ts=4 fdm=marker:
--[[
    Copyright 2008 Ali Polatel <polatel@itu.edu.tr>

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to
    deal in the Software without restriction, including without limitation the
    rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
    sell copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
    IN THE SOFTWARE.
--]]

require("lunit")
require("tc")

function hexdigest(buf)
    local hexdigest = ""
    for i=1, #buf do
        hexdigest = hexdigest .. string.format("%02x", string.byte(buf:sub(i, i)))
    end
    return hexdigest
end

module("hashtest", package.seeall, lunit.testcase)

function test_hash_string()
    instring = "Lather was 30 years old today"
    EXPECTED = "1a0932cd8e996b62b6b3b030d449307a"

    assert(tc.register_hash(tc.md5_desc), "tc.register_hash() failed")
    idx = assert(tc.find_hash("md5"), "tc.find_hash() failed")
    h, b = tc.hash_string(idx, instring)
    assert(h, "tc.hash_string() failed")

    assert(tc.unregister_hash(tc.md5_desc), "tc.unregister_hash() failed")

    assert(hexdigest(h) == EXPECTED, "(hash_string) md5 digests don't match")
    assert(b == 16, "(hash_string) blocksizes don't match")
end

function test_hash_file()
    infile = "test/test-hashfile.txt"
    EXPECTED = "5854a1b2035d0166f4f28d14e963f428"

    assert(tc.register_hash(tc.md5_desc), "tc.register_hash() failed")
    idx = assert(tc.find_hash("md5"), "tc.find_hash() failed")
    h, b = tc.hash_file(idx, infile)
    assert(h, "tc.hash_file() failed")

    assert(hexdigest(h) == EXPECTED, "(hash_file) md5 digests don't match")
    assert(b == 16, "(hash_file) blocksizes don't match")
end

function test_whirlpool()
    instring = "Stairway scare, Dan Dare, who's there?"
    EXPECTED = "45f4614ca355239ffe45919b86a4e717590e181" ..
               "8c4083e0794699f0e2e78f90b95280f5ad9be80" ..
               "eaf0481479c2167972c9ccee11525c80345689a" ..
               "00b295dd4a4"

    hashstate = assert(tc.whirlpool_init(), "tc.whirlpool_init() failed")
    assert(tc.whirlpool_process(hashstate, instring), "tc.whirlpool_process() failed")
    h = assert(tc.whirlpool_done(hashstate), "tc.whirlpool_done() failed")
    assert(hexdigest(h) == EXPECTED, "whirlpool digests don't match")
end

function test_sha512()
    instring = "Remember what the dormouse said!"
    EXPECTED = "13956160a15d0ae9d3ed1a83a51e401c" ..
               "c461ae97773b5e20f61201add080afa1" ..
               "ad30a3c0ac8cf3f99dd13ddb40509fcc" ..
               "45b26dee66cf3a8bdc09dd705d2f5d3c"

    hashstate = assert(tc.sha512_init(), "tc.sha512_init() failed")
    assert(tc.sha512_process(hashstate, instring), "tc.sha512_process() failed")
    h = assert(tc.sha512_done(hashstate), "tc.sha512_done() failed")
    assert(hexdigest(h) == EXPECTED, "sha512 digests don't match")
end

function test_sha384()
    instring = "Jupiter and Saturn, Oberon, Miranda and Titania, " ..
               "Neptune, Titan, stars can frighten."
    EXPECTED = "29fd4dc6409955703ecc7d79541f147" ..
               "479f00c15e624767a7a2910dc457ce7" ..
               "04f0dbd643419ad3da48879c6f6723360a"

    hashstate = assert(tc.sha384_init(), "tc.sha384_init() failed")
    assert(tc.sha384_process(hashstate, instring), "tc.sha384_process() failed")
    h = assert(tc.sha384_done(hashstate), "tc.sha384_done() failed")
    assert(hexdigest(h) == EXPECTED, "sha384 digests don't match")
end

function test_sha256()
    instring = "Careful with that axe, Eugene. Ahhhhhhhhhhhhh!"
    EXPECTED = "8e9579941274b78cae7943e8ec7c732" ..
               "56a7853d08618e69288161a870708582e"

    hashstate = assert(tc.sha256_init(), "tc.sha256_init() failed")
    assert(tc.sha256_process(hashstate, instring), "tc.sha256_process() failed")
    h = assert(tc.sha256_done(hashstate), "tc.sha256_done() failed")
    assert(hexdigest(h) == EXPECTED, "sha256 digests don't match")
end

function test_sha224()
    instring = "One of the things you learn after years " ..
               "of dealing with drug people, is that you " ..
               "can turn your back on a person, but never " ..
               "turn your back on a drug."
    EXPECTED = "3a767642e55e7eb09d868ea08bb4457911c30877e8cade86206063b3"

    hashstate = assert(tc.sha224_init(), "tc.sha224_init() failed")
    assert(tc.sha224_process(hashstate, instring), "tc.sha224_process() failed")
    h = assert(tc.sha224_done(hashstate), "tc.sha224_done() failed")
    assert(hexdigest(h) == EXPECTED, "sha224 digests don't match")
end

function test_sha1()
    instring = "I'm an alligator, I'm a mama-papa comin' for you"
    EXPECTED = "be4172d54e1d259b18d0f97ea62d3397653b9e4a"

    hashstate = assert(tc.sha1_init(), "tc.sha1_init() failed")
    assert(tc.sha1_process(hashstate, instring), "tc.sha1_process() failed")
    h = assert(tc.sha1_done(hashstate), "tc.sha1_done() failed")
    assert(hexdigest(h) == EXPECTED, "sha1 digests don't match")
end

function test_md5()
    instring = "Oh, wanna whole lotta love"
    EXPECTED = "69e87bf697645de3bc63fa5d6aef8876"

    hashstate = assert(tc.md5_init(), "tc.md5_init() failed")
    assert(tc.md5_process(hashstate, instring), "tc.md5_process() failed")
    h = assert(tc.md5_done(hashstate), "tc.md5_done() failed")

    assert(hexdigest(h) == EXPECTED, "md5 digests don't match")
end

function test_md4()
    instring = "An Effervescing Elephant with tiny eyes and great big trunk"
    EXPECTED = "1eb8697ddcf90821ac055b2d90b25db3"

    hashstate = assert(tc.md4_init(), "tc.md4_init() failed")
    assert(tc.md4_process(hashstate, instring), "tc.md4_process() failed")
    h = assert(tc.md4_done(hashstate), "tc.md4_done() failed")
    assert(hexdigest(h) == EXPECTED, "md4 digests don't match")
end

function test_md2()
    instring = "Please leave us here Close our eyes to the octopus ride!"
    EXPECTED = "0acda2a912a71a89733b8ad3f8f9c45d"

    hashstate = assert(tc.md2_init(), "tc.md2_init() failed")
    assert(tc.md2_process(hashstate, instring), "tc.md2_process() failed")
    h = assert(tc.md2_done(hashstate), "tc.md2_done() failed")
    assert(hexdigest(h) == EXPECTED, "md2 digests don't match")
end

function test_tiger()
    instring = "Father? Yes son? I want to kill you"
    EXPECTED = "fca12e3b035a3d366510e3be9f41f5432b819f74f70418de"

    hashstate = assert(tc.tiger_init(), "tc.tiger_init() failed")
    assert(tc.tiger_process(hashstate, instring), "tc.tiger_process() failed")
    h = assert(tc.tiger_done(hashstate), "tc.tiger_done() failed")
    assert(hexdigest(h) == EXPECTED, "tiger digests don't match")
end

function test_rmd128()
    instring = "For if we don't find the next little girl I tell you we must die"
    EXPECTED = "1fdb9fc969d811f5f32ce7b72e9dc69a"

    hashstate = assert(tc.rmd128_init(), "tc.rmd128_init() failed")
    assert(tc.rmd128_process(hashstate, instring), "tc.rmd128_process() failed")
    h = assert(tc.rmd128_done(hashstate), "tc.rmd128_done() failed")
    assert(hexdigest(h) == EXPECTED, "rmd128 digests don't match")
end

function test_rmd160()
    instring = "I am the Eggman they are the Eggmen I am the Walrus"
    EXPECTED = "b709b85d2abe2ed16a50564c4684ec33"

    hashstate = assert(tc.rmd160_init(), "tc.rmd160_init() failed")
    assert(tc.rmd160_process(hashstate, instring), "tc.rmd160_process() failed")
    h = assert(tc.rmd160_done(hashstate), "tc.rmd160_done() failed")
    assert(hexdigest(h) == EXPECTED, "rmd160 digests don't match")
end

function test_rmd256()
    instring = "I read the news today, oh boy"
    EXPECTED = "303056cbb9cbc226df42d7caf36b65918bad82354e752927c3d12eaa8a971113"

    hashstate = assert(tc.rmd256_init(), "tc.rmd256_init() failed")
    assert(tc.rmd256_process(hashstate, instring), "tc.rmd256_process() failed")
    h = assert(tc.rmd256_done(hashstate), "tc.rmd256_done() failed")
    assert(hexdigest(h) == EXPECTED, "rmd256 digests don't match")
end

function test_rmd320()
    instring = "Lucy in the Sky with Diamonds"
    EXPECTED = "509132f54c08067d8f74dbe6626c289" ..
               "2f0b89f66148012c8e51d501f02018c88808ca29a380e6df8"

    hashstate = assert(tc.rmd320_init(), "tc.rmd320_init() failed")
    assert(tc.rmd320_process(hashstate, instring), "tc.rmd320_process() failed")
    h = assert(tc.rmd320_done(hashstate), "tc.rmd320_done() failed")
    assert(hexdigest(h) == EXPECTED, "rmd320 digests don't match")
end

