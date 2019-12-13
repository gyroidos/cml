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

LOCAL_CFLAGS := -std=gnu99 -Icommon -I.. -I../include -O2 -pedantic
LOCAL_CFLAGS += -Wall -Wextra -Wcast-align -Wformat -Wformat-security -Werror -fstack-protector-all -fstack-clash-protection -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now -fpic -pie
LOCAL_CFLAGS += -DDEBUG_BUILD
# set for sending boot complete protobuf message only
#LOCAL_CFLAGS += -DBOOT_COMPLETE_ONLY


SRC_FILES := \
	common/list.c \
	common/logf.c \
	common/mem.c \
	common/protobuf.c \
	common/sock.c \
	common/file.c \
	common/fd.c \
	dumb_init.c \
	c_service.pb-c.c \
	container.pb-c.c \
	control.pb-c.c \
	guestos.pb-c.c \
	common/logf.pb-c.c \
	service.c

.PHONY: all
all: service

protobuf: c_service.proto container.proto control.proto guestos.proto common/logf.proto
	protoc-c --c_out=. c_service.proto
	protoc-c --c_out=. container.proto
	protoc-c --c_out=. control.proto
	protoc-c --c_out=. guestos.proto
	$(MAKE) -C common protobuf

$(SRC_FILES): protobuf

service: $(SRC_FILES)
	$(CC) $(LOCAL_CFLAGS) $(CLAGS) $(SRC_FILES) -lprotobuf-c -lprotobuf-c-text -o cml-service-container

service-static: $(SRC_FILES)
	$(CC) -static $(LOCAL_CFLAGS) $(CFLAGS) $(SRC_FILES) -lprotobuf-c -lprotobuf-c-text -o cml-service-container


.PHONY: clean
clean:
	rm -f cml-service-container *.o *.pb-c.*
