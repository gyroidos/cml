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

LOCAL_CFLAGS := -std=gnu99 -I.. -I../include -I../tpm2d -Icommon -DDEBUG_BUILD -O2
LOCAL_CFLAGS += -DTPM_POSIX

SRC_FILES := \
	common/list.c \
	common/logf.c \
	common/mem.c \
	common/sock.c \
	common/event.c \
	common/str.c \
	common/file.c \
	common/dir.c \
	common/fd.c \
	common/uuid.c \
	common/protobuf.c \
	common/reboot.c \
	device.pb-c.c \
	scd.pb-c.c \
	control.c \
	softtoken.c \
	scd.c \
	ssl_util.c


.PHONY: all
all: scd


protobuf: device.proto scd.proto
	protoc-c --c_out=. scd.proto
	protoc-c --c_out=. device.proto

${SRC_FILES}: protobuf

libcommon:
	$(MAKE) -C common libcommon

scd: libcommon ${SRC_FILES}
	${CC} ${LOCAL_CFLAGS} ${SRC_FILES} -lc -lprotobuf-c -lprotobuf-c-text -lssl -lcrypto -Lcommon -lcommon -o scd


.PHONY: clean
clean:
	rm -f scd *.o *.pb-c.*
