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
CC_MODE ?= n

TRUSTME_HARDWARE := x86

LOCAL_CFLAGS := -std=gnu99 -Icommon -I.. -I../include -I../tpm2d -I../scd -pedantic -O2
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
ifeq ($(CC_MODE),y)
    # build for restrictive CC mode
    LOCAL_CFLAGS += -DCC_MODE
endif

LDLIBS := -lc -lprotobuf-c -lprotobuf-c-text -lselinux -Lcommon -lcommon -lutil

.PHONY: all
all: cmld

PROTO_SRC := \
	container.pb-c.c \
	control.pb-c.c \
	guestos.pb-c.c \
	common/logf.pb-c.c \
	device.pb-c.c \
	scd.pb-c.c \
	attestation.pb-c.c \
	tpm2d.pb-c.c \
	common/audit.pb-c.c \
	c_service.pb-c.c

SRC_FILES := main.c \
	cmld.c \
	uevent.c \
	container.c \
	common/uuid.c \
	control.c \
	container_config.c \
	device_config.c \
	mount.c \
	guestos.c \
	guestos_mgr.c \
	guestos_config.c \
	common/protobuf.c \
	download.c \
	smartcard.c \
	tss.c \
	common/sock.c \
	c_cgroups.c \
	c_service.c \
	c_net.c \
	c_user.c \
	c_vol.c \
	common/network.c \
	common/proc.c \
	common/loopdev.c \
	ksm.c \
	c_cap.c \
	common/cryptfs.c \
	common/reboot.c \
	c_run.c \
	c_fifo.c \
	c_time.c \
	time.c \
	hw_$(TRUSTME_HARDWARE).c \
	lxcfs.c \
	input.c \
	common/audit.c \
	audit.c \
	c_audit.c

ifeq ($(CC_MODE),y)
protobuf: container.proto control.proto guestos.proto common/logf.proto device.proto scd.proto common/audit.proto c_service.proto
	$(MAKE) -C cc_mode
	ln -sf cc_mode/guestos.pb-c.c guestos.pb-c.c
	ln -sf cc_mode/guestos.pb-c.h guestos.pb-c.h
	ln -sf cc_mode/device.pb-c.c device.pb-c.c
	ln -sf cc_mode/device.pb-c.h device.pb-c.h
	protoc-c --c_out=. container.proto
	protoc-c --c_out=. control.proto
	protoc-c --c_out=. scd.proto
	protoc-c --c_out=. attestation.proto
	protoc-c --c_out=. tpm2d.proto
	protoc-c --c_out=. c_service.proto
	$(MAKE) -C common protobuf

else
protobuf: container.proto control.proto guestos.proto common/logf.proto device.proto scd.proto common/audit.proto c_service.proto
	protoc-c --c_out=. container.proto
	protoc-c --c_out=. control.proto
	protoc-c --c_out=. guestos.proto
	protoc-c --c_out=. device.proto
	protoc-c --c_out=. scd.proto
	protoc-c --c_out=. attestation.proto
	protoc-c --c_out=. tpm2d.proto
	protoc-c --c_out=. c_service.proto
	$(MAKE) -C common protobuf

endif

$(PROTO_SRC): protobuf

libcommon:
	$(MAKE) -C common libcommon

cmld: libcommon $(PROTO_SRC) $(SRC_FILES)
	$(CC) $(LOCAL_CFLAGS) $(SRC_FILES) $(PROTO_SRC) $(LDLIBS) -o cmld


.PHONY: clean
clean:
	rm -f cmld *.o *.pb-c.*
	$(MAKE) -C common clean
