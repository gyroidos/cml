#
# This file is part of GyroidOS
# Copyright(c) 2013 - 2020 Fraunhofer AISEC
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
# Fraunhofer AISEC <gyroidos@aisec.fraunhofer.de>
#


CC ?= gcc
DEVELOPMENT_BUILD ?= y
AGGRESSIVE_WARNINGS ?= n
SANITIZERS ?= n

LOCAL_CFLAGS := -std=gnu99 -Icommon -I.. -I../include -pedantic -O2
LOCAL_CFLAGS += -Wall -Wextra -Wcast-align -Wformat -Wformat-security -fstack-protector-all -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now -fpic -pie

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


PROTO_SRC := \
	common/logf.pb-c.c \
	container.pb-c.c \
	control.pb-c.c \
	guestos.pb-c.c

SRC_FILES := \
	cJSON/cJSON.c \
	util.c \
	docker.c \
	control.c \
	converter.c

LD_LIB_FLAGS := \
	-Lcommon -lcommon_ext \
	-lprotobuf-c \
	-lprotobuf-c-text \
	-lresolv \
	-lcrypto

.PHONY: all
all: converter

protobuf: container.proto control.proto guestos.proto common/logf.proto
	protoc-c --c_out=. guestos.proto
	protoc-c --c_out=. container.proto
	protoc-c --c_out=. control.proto
	$(MAKE) -C common protobuf

$(PROTO_SRC): protobuf

libcommon:
	$(MAKE) -C common libcommon_ext

converter: libcommon $(SRC_FILES) $(PROTO_SRC)
	$(CC) $(LOCAL_CFLAGS) $(SRC_FILES) $(PROTO_SRC) $(LD_LIB_FLAGS) -o $@


.PHONY: clean
clean:
	rm -f converter *.o *.pb-c.*
	$(MAKE) -C common clean

