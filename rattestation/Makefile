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

LOCAL_CFLAGS := -std=gnu99 -Icommon -I.. -I../include -pedantic -O2
LOCAL_CFLAGS += -DDEBUG_BUILD
LOCAL_CFLAGS += -Wall -Wextra -Wcast-align -Wformat -Wformat-security -Werror -fstack-protector-all -fstack-clash-protection -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now -fpic -pie

PROTO_SRC := \
	attestation.pb-c.c

SRC_FILES := \
	common/protobuf.c \
	common/fd.c \
	common/sock.c \
	common/file.c \
	attestation.c \
	main.c

.PHONY: all
all: rattestation

protobuf: attestation.proto
	protoc-c --c_out=. attestation.proto
	$(MAKE) -C common protobuf

${PROTO_SRC}: protobuf

libcommon:
	$(MAKE) -C common libcommon

rattestation: libcommon ${SRC_FILES} ${PROTO_SRC}
	${CC} -static ${LOCAL_CFLAGS} ${SRC_FILES} ${PROTO_SRC} -lprotobuf-c -lprotobuf-c-text -Lcommon -lcommon -o $@


.PHONY: clean
clean:
	rm -f rattestation *.o *.pb-c.*
