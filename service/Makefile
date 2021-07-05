#
# This file is part of trust|me
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
# Fraunhofer AISEC <trustme@aisec.fraunhofer.de>
#


CC ?= gcc
DEVELOPMENT_BUILD ?= y
AGGRESSIVE_WARNINGS ?= y
SANITIZERS ?= n
WCAST_ALIGN ?= y

LOCAL_CFLAGS := -std=gnu99 -Icommon -I.. -I../include -O2 -pedantic
LOCAL_CFLAGS += -Wall -Wextra -Wformat -Wformat-security -fstack-protector-all -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now -fpic -pie
# set for sending boot complete protobuf message only
#LOCAL_CFLAGS += -DBOOT_COMPLETE_ONLY
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
	dumb_init.c \
	c_service.pb-c.c \
	container.pb-c.c \
	control.pb-c.c \
	guestos.pb-c.c \
	common/logf.pb-c.c \
	service.c

SRC_FILES_EXEC_CAP_SYSTIME := \
	c_service.pb-c.c \
	container.pb-c.c \
	control.pb-c.c \
	guestos.pb-c.c \
	common/logf.pb-c.c \
	exec_cap_systime.c

LD_LIB_FLAGS := \
	-Lcommon -lcommon_full \
	-lprotobuf-c \
	-lprotobuf-c-text

.PHONY: all
all: service exec_cap_systime

protobuf: c_service.proto container.proto control.proto guestos.proto common/logf.proto
	protoc-c --c_out=. c_service.proto
	protoc-c --c_out=. container.proto
	protoc-c --c_out=. control.proto
	protoc-c --c_out=. guestos.proto
	$(MAKE) -C common protobuf

$(SRC_FILES): protobuf

libcommon:
	$(MAKE) -C common libcommon_full

service: libcommon $(SRC_FILES)
	$(CC) $(LOCAL_CFLAGS) $(CLAGS) $(SRC_FILES) ${LD_LIB_FLAGS} -o cml-service-container

service-static: libcommon $(SRC_FILES)
	$(CC) -static $(LOCAL_CFLAGS) $(CFLAGS) $(SRC_FILES) ${LD_LIB_FLAGS} -o cml-service-container

exec_cap_systime: libcommon $(SRC_FILES_EXEC_CAP_SYSTIME)
	$(CC) -static $(LOCAL_CFLAGS) $(CFLAGS) $(SRC_FILES_EXEC_CAP_SYSTIME) ${LD_LIB_FLAGS} -o exec_cap_systime


.PHONY: clean
clean:
	rm -f cml-service-container exec_cap_systime *.o *.pb-c.*
	$(MAKE) -C common clean
