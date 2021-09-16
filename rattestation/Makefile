#
# This file is part of trust|me
# Copyright(c) 2013 - 2019 Fraunhofer AISEC
# Fraunhofer-Gesellschaft zur Förderung der angewandten Forschung e.V.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms and conditions of the GNU General Public License,
# version 2 (GPL 2), as published by the Free Software Foundation.
#
# This program is distributed in the hope it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GPL 2 license for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, see <http://www.gnu.org/licenses/>
#
# The full GNU General Public License is included in this distribution in
# the file called "COPYING".
#
# Contact Information:
# Fraunhofer AISEC <trustme@aisec.fraunhofer.de>
#


CC ?= gcc
DEVELOPMENT_BUILD ?= y
AGGRESSIVE_WARNINGS ?= n
SANITIZERS ?= n
WCAST_ALIGN ?= y
STATIC = # -static TODO OpenSSL causes segfault with -static

LOCAL_CFLAGS := -std=gnu99 -Icommon -I.. -I../include -pedantic -O2
LOCAL_CFLAGS += -Wall -Wextra -Wformat -Wformat-security -fstack-protector-all -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now -fpic -pie
ifeq ($(WCAST_ALIGN),y)
    LOCAL_CFLAGS += -Wcast-align
endif
ifeq ($(CC),gcc)
    # clang does not support stack clash protection yet
    LOCAL_CFLAGS += -fstack-clash-protection
endif
ifeq ($(DEVELOPMENT_BUILD),y)
    # what are we building? development or production code?
    LOCAL_CFLAGS += -DDEBUG_BUILD
endif
ifeq ($(AGGRESSIVE_WARNINGS),y)
    # on CI (and also for well-behaved developers) warnings should be
    # converted to errors; this helps us redistribute the code base without any pain;
    # pure builds are better than polluted builds.
    LOCAL_CFLAGS += -Werror
endif
ifeq ($(SANITIZERS),y)
    # if requested, we enable sanitization for easier debugging
    # this requires libasan libasan-static libubsan libubsan-static
    # to be installed on the build host
    LOCAL_CFLAGS += -fsanitize=address -fsanitize=undefined
    # we can't use sanitiziers with static linking
    # ASan simply doesn't support it
    STATIC =
endif


PROTO_SRC := \
	attestation.pb-c.c \
	config.pb-c.c

SRC_FILES := \
	common/protobuf.c \
	attestation.c \
	hash.c \
	ima_verify.c \
	container_verify.c \
	config.c \
	modsig.c \
	main.c

.PHONY: all
all: rattestation

protobuf: attestation.proto
	protoc-c --c_out=. attestation.proto config.proto
	$(MAKE) -C common protobuf

$(PROTO_SRC): protobuf

libcommon:
	$(MAKE) -C common libcommon_ext

rattestation: libcommon $(SRC_FILES) $(PROTO_SRC)
	$(CC) $(STATIC) $(LOCAL_CFLAGS) $(SRC_FILES) $(PROTO_SRC) -lprotobuf-c -lprotobuf-c-text -Lcommon -lcommon_ext -lssl -lcrypto -libmtss -o $@

.PHONY: clean
clean:
	rm -f rattestation *.o *.pb-c.*
	$(MAKE) -C common clean
