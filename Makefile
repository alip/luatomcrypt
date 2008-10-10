# LuaTomCrypt's Makefile

CFLAGS+=-fPIC -shared -Wall -g -O2 $(shell pkg-config --cflags lua)
LDFLAGS+=$(shell pkg-config --libs lua)
ifdef TOMSFASTMATH
	LDFLAGS+= -ltomsfastmath
else
	LDFLAGS+= -ltommath
endif
LDFLAGS+= -ltomcrypt

tc.so: tomcrypt.c tomcrypt_hash.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ tomcrypt.c

test:
	lunit test/*.lua

clean:
	rm -f *.o *.so || true

.PHONY: clean test
