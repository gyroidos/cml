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
LOCAL_CFLAGS := -std=gnu99 -Icommon -I.. -I../include -DDEBUG_BUILD

TRUSTME_HARDWARE := ppc

.PHONY: all
all: cmld

PROTO_SRC := \
	container.pb-c.c \
	control.pb-c.c \
	guestos.pb-c.c \
	common/logf.pb-c.c \
	device.pb-c.c \
	scd.pb-c.c \
	c_service.pb-c.c

SRC_FILES := main.c \
	cmld.c \
	container.c \
	common/uuid.c \
	control.c \
	container_config.c \
	device_config.c \
	common/file.c \
	common/dir.c \
	common/fd.c \
	mount.c \
	guestos.c \
	guestos_mgr.c \
	guestos_config.c \
	common/protobuf.c \
	download.c \
	smartcard.c \
	common/sock.c \
	c_cgroups.c \
	c_service.c \
	display.c \
	c_net.c \
	c_vol.c \
	common/network.c \
	common/proc.c \
	common/loopdev.c \
	ksm.c \
	c_cap.c \
	common/cryptfs.c \
	common/reboot.c \
	power.c \
	hw_$(TRUSTME_HARDWARE).c

protobuf: container.proto control.proto guestos.proto common/logf.proto device.proto scd.proto c_service.proto
	protoc-c --c_out=. container.proto
	protoc-c --c_out=. control.proto
	protoc-c --c_out=. guestos.proto
	protoc-c --c_out=. device.proto
	protoc-c --c_out=. scd.proto
	protoc-c --c_out=. c_service.proto
	$(MAKE) -C common protobuf

${PROTO_SRC}: protobuf

libcommon:
	$(MAKE) -C common libcommon

cmld: libcommon ${PROTO_SRC} ${SRC_FILES}
	${CC} ${LOCAL_CFLAGS} ${SRC_FILES} ${PROTO_SRC} -lc -lprotobuf-c -lprotobuf-c-text -lselinux -Lcommon -lcommon -o cmld


.PHONY: clean
clean:
	rm -f cmld *.o *.pb-c.*
