#  Copyright 2022 Ye Holmes <yeholmes@outlook.com>
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

MAKEFLAGS += -r -R
CC        ?= gcc
STRIP     ?= strip


CFLAGS     = -Wall -Wno-unused-result -fPIC -D_GNU_SOURCE -ggdb -Os
CFLAGS    += -I. -I$(LUA_INCDIR) $(EXTRA_CFLAGS)
LDFLAGS   := -lpthread
TARGETS    = apputil.o base64.o sysutil.so sysutil.o zsha256_util.o zsha256_test.o zsha256

.PHONY: all clean
all: $(TARGETS)

sysutil.so: sysutil.o apputil.o zsha256_util.o base64.o
	$(CC) -shared -o $@ $^ -lpthread
	$(STRIP) -s $@

zsha256: zsha256_test.o zsha256_util.o apputil.o
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c apputil.h
	$(CC) -c $(CFLAGS) -o $@ $<

install:
	@true

clean:
	rm -rf *.o $(TARGETS)
