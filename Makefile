CC      ?= cc
CFLAGS  ?= -shared -fPIC -O2 -Wall
PREFIX  ?= $(HOME)/.local/lib/fakesecret

all: libsecret-1.so.0

libsecret-1.so.0: fakesecret.c
	$(CC) $(CFLAGS) -o $@ $<

install: libsecret-1.so.0
	install -d $(PREFIX)
	install -m 755 libsecret-1.so.0 $(PREFIX)/libsecret-1.so.0
	install -m 644 fakesecret.c $(PREFIX)/fakesecret.c
	@echo "Shim installed to $(PREFIX)"
	@echo "Now run ./install.sh to add the proton-drive wrapper,"
	@echo "or set LD_LIBRARY_PATH=$(PREFIX) yourself."

clean:
	rm -f libsecret-1.so.0

.PHONY: all install clean
