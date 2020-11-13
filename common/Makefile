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

LOCAL_CFLAGS += -I../include -pedantic -std=gnu99 -D _POSIX_C_SOURCE=200809L -D _XOPEN_SOURCE=700 -D _DEFAULT_SOURCE -O2
LOCAL_CFLAGS += -Wall -Wextra -Wcast-align -Wformat -Wformat-security -fstack-protector-all -fPIC
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
	fd.o \
	file.o \
	dir.o \
	ns.o \
	nl.o

OBJS_COMMON_FULL := \
	$(OBJS_COMMON) \
	protobuf.o \
	logf.pb-c.o \
	sock.o \
	network.o \
	proc.o \
	loopdev.o

libcommon: $(OBJS_COMMON)
	ar rcs libcommon.a $^

libcommon_full: $(OBJS_COMMON_FULL)
	ar rcs libcommon_full.a $^

%.o: %.c
	$(CC) -c $(LOCAL_CFLAGS) $< -o $@
	
logf.pb-c.c: logf.proto
	protoc-c --c_out=. $<

TEST_SUITES := \
    mem.test.c \
    macro.test.c

common.test: $(TEST_SUITES) munit.h munit.c common.test.c
	$(CC) $(LOCAL_CFLAGS) -o $@ $(OBJS_COMMON) $(TEST_SUITES) munit.c common.test.c

.PHONY: test
test: libcommon_full common.test
	./common.test

.PHONY: clean
clean:
	rm -f *.o *.a *.pb-c.* common.test
