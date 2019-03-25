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

LOCAL_CFLAGS += -I../include -pedantic -Wall -Wextra -Werror -std=gnu99 -D _POSIX_C_SOURCE=200809L -D _XOPEN_SOURCE=700 -D _DEFAULT_SOURCE

.PHONY: all
all: libcommon

.PHONY: protobuf
protobuf: logf.pb-c.c

OBJS_COMMON := \
	event.o \
	list.o \
	logf.o \
	mem.o \
	str.o \
	nl.o

OBJS_COMMON_FULL := \
	$(OBJS_COMMON) \
	protobuf.o \
	logf.pb-c.o \
	file.o \
	dir.o \
	fd.o \
	sock.o \
	network.o \
	proc.o \
	loopdev.o

libcommon: $(OBJS_COMMON)
	ar rcs libcommon.a $^

libcommon_full: $(OBJS_COMMON_FULL)
	ar rcs libcommon_full.a $^

.c.o:
	${CC} -c ${LOCAL_CFLAGS} $< -o $@
	

logf.pb-c.c: logf.proto
	protoc-c --c_out=. $<

.PHONY: clean
clean:
	rm -f *.o *.a *.pb-c.*
