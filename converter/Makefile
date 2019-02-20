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

LOCAL_CFLAGS := -std=gnu99 -Icommon -I.. -I../include -DDEBUG_BUILD -pedantic -Wall -Wextra -Werror

PROTO_SRC := \
	guestos.pb-c.c

SRC_FILES := \
	common/protobuf.c \
	common/dir.c \
	common/file.c \
	common/fd.c \
	cJSON/cJSON.c \
	gzopen.c \
	util.c \
	docker.c \
	converter.c

LD_LIB_FLAGS := \
	-Lcommon -lcommon \
	-lprotobuf-c \
	-lprotobuf-c-text \
	-lz \
	-ltar \
	-lresolv \
	-lcrypto

.PHONY: all
all: converter

protobuf: guestos.proto
	protoc-c --c_out=. guestos.proto
	$(MAKE) -C common protobuf

${PROTO_SRC}: protobuf

libcommon:
	$(MAKE) -C common libcommon

converter: libcommon ${SRC_FILES} ${PROTO_SRC}
	${CC} ${LOCAL_CFLAGS} ${SRC_FILES} ${PROTO_SRC} ${LD_LIB_FLAGS} -o $@


.PHONY: clean
clean:
	rm -f converter *.o *.pb-c.*

