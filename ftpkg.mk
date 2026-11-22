#
# Copyright 2021 Ye Holmes <yeholmes@outlook.com>
#
# Makefile template for Fighter package

PKG_NAME :=sysutil
PKG_DEFAULT :=y

ifndef FTPKG_GENERATING
MAKEFLAGS += -r -R

include $(FT_PKGINC)

# do not leak upper level make flags:
unexport MFLAGS
unexport MAKEFLAGS

CFLAGS   :=$(FT_CFLAGS) -D_GNU_SOURCE \
	-I$(FT_DESTPFX)/include -fPIC -D_FILE_OFFSET_BITS=64
LDFLAGS  :=$(FT_LDFLAGS) -lpthread

.PHONY: prepare compile install clean
prepare:
	@echo "Nothing TODO to prepare for $(PKG_NAME)" ; exit 0
compile: sysutil.so
sysutil.so: sysutil.o apputil.o zsha256_util.o base64.o
	$(FT_CC) -shared -o $@ $^ -lpthread
	$(FT_CLPFX)strip -s $@
%.o: %.c apputil.h
	$(FT_CC) -c $(CFLAGS) -o $@ $<
install: sysutil.so
	@mkdir -p $(FT_DESTPFX)/lib/lua
	@cp -v $^ $(FT_DESTPFX)/lib/lua/
clean:
	@rm -rf *.o *.a *.so*

endif # FTPKG_GENERATING
