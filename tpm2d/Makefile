#
# This file is part of trust|me
# Copyright(c) 2013 - 2018 Fraunhofer AISEC
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
AGGRESSIVE_WARNINGS ?= y
SANITIZERS ?= n
WCAST_ALIGN ?= y

tss_cflags := \
        -Wall -W -Wmissing-declarations -Wmissing-prototypes -Wnested-externs \
	-DTPM_POSIX

LOCAL_CFLAGS := -std=gnu99 -I. -I.. -I../include -Icommon $(tss_cflags) -O2
LOCAL_CFLAGS += -Wextra -Wformat -Wformat-security -fstack-protector-all -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now -fpic -pie
#LOCAL_CFLAGS += -DTPM2D_NVMCRYPT_ONLY
ifeq ($(WCAST_ALIGN),y)
    LOCAL_CFLAGS += -Wcast-align
endif
ifeq ($(CC),gcc)
    # clang does not support stack clash protection yet
    LOCAL_CFLAGS += -fstack-clash-protection
endif
ifeq ($(DEVELOPMENT_BUILD),y)
    # what are we building? development or production code?
    LOCAL_CFLAGS += -ggdb -DDEBUG_BUILD
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
    LOCAL_CFLAGS += -lasan -fsanitize=address -fsanitize=undefined -fsanitize-recover=address
endif


SRC_FILES := \
	common/dir.c \
	common/file.c \
	common/fd.c \
	common/sock.c \
	common/protobuf.c \
	common/cryptfs.c \
	common/dm.c \
	attestation.pb-c.c \
	tpm2d.pb-c.c \
	control.c \
	rcontrol.c \
	tpm2_commands.c \
	nvmcrypt.c \
	ml.c \
	ek.c \
	tpm2-asn.c \
	tpm2d.c \
	tpm2d_write_openssl.c


.PHONY: all
all: tpm2d

protobuf: attestation.proto tpm2d.proto
	protoc-c --c_out=. attestation.proto
	protoc-c --c_out=. tpm2d.proto

$(SRC_FILES): protobuf

libcommon:
	$(MAKE) -C common libcommon

tpm2d: libcommon $(SRC_FILES)
	$(CC) $(LOCAL_CFLAGS) $(SRC_FILES) -lc -lprotobuf-c -lprotobuf-c-text -libmtss -lcrypto -Lcommon -lcommon -o tpm2d

.PHONY: clean
clean:
	rm -f tpm2d *.o *.pb-c.*
	$(MAKE) -C common clean
