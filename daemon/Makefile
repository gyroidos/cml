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
AGGRESSIVE_WARNINGS ?= y
SANITIZERS ?= n
CC_MODE ?= n
WCAST_ALIGN ?= y
OCI ?= n
IDMAPPED ?= n
CGROUP_V2 ?= y
CGROUP_SOCKOPT ?= n
SYSTEMD ?= n

TRUSTME_HARDWARE := x86

LOCAL_CFLAGS := -std=gnu99 -Icommon -I.. -I../include -I../tpm2d -I../scd -pedantic -O2
LOCAL_CFLAGS += -Wall -Wextra -Wformat -Wformat-security -fstack-protector-all -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now -fpic -pie
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
ifeq ($(CC_MODE),y)
    # build for restrictive CC mode
    LOCAL_CFLAGS += -DCC_MODE
endif

LDLIBS := -lc -Lcommon -lcommon_full -lutil -lprotobuf-c -lprotobuf-c-text

.PHONY: all
all: cmld

PROTO_SRC := \
	container.pb-c.c \
	control.pb-c.c \
	guestos.pb-c.c \
	device.pb-c.c \
	scd.pb-c.c \
	attestation.pb-c.c \
	tpm2d.pb-c.c \
	c_service.pb-c.c

SRC_FILES := main.c \
	cmld.c \
	hotplug.c \
	container.c \
	compartment.c \
	control.c \
	container_config.c \
	device_config.c \
	mount.c \
	guestos.c \
	guestos_mgr.c \
	guestos_config.c \
	download.c \
	crypto.c \
	scd.c \
	tss.c \
	ksm.c \
	time.c \
	hw_$(TRUSTME_HARDWARE).c \
	lxcfs.c \
	input.c \
	audit.c

# module order is crucial
SRC_CMODULES := \
	c_smartcard.c \
	c_user.c

ifeq ($(IDMAPPED),y)
SRC_CMODULES += \
	c_idmapped.c
else
SRC_CMODULES += \
	c_shiftid.c
endif

ifeq ($(SYSTEMD),y)
    SRC_CMODULES += \
	c_cgroups_systemd.c
    LDLIBS += -lsystemd
endif

ifeq ($(CGROUP_V2),y)
    SRC_CMODULES += \
	c_cgroups_v2.c \
	c_cgroups_dev.c
ifeq ($(CGROUP_SOCKOPT),y)
    SRC_CMODULES += \
	c_cgroups_sockopt.c
endif
else
    SRC_CMODULES += \
	c_cgroups.c
    LOCAL_CFLAGS += -DCGROUPS_LEGACY
endif

SRC_CMODULES += \
	c_net.c \
	c_vol.c \
	c_service.c \
	c_run.c \
	c_fifo.c \
	c_time.c \
	c_audit.c \
	c_cap.c \
	c_uevent.c \
	c_hotplug.c \
	c_seccomp.c

ifeq ($(OCI),y)
    LOCAL_CFLAGS += -DOCI -I${HOME}/rcs/libocispec/src
    LDLIBS += -locispec -L${HOME}/rcs/libocispec/.libs -lyajl
    PROTO_SRC += oci_control.pb-c.c
    SRC_FILES += oci.c
    SRC_CMODULES += c_oci.c
endif


ifeq ($(CC_MODE),y)
protobuf: container.proto control.proto guestos.proto device.proto scd.proto common/audit.proto c_service.proto
	$(MAKE) -C cc_mode
	ln -sf cc_mode/container.pb-c.c container.pb-c.c
	ln -sf cc_mode/container.pb-c.h container.pb-c.h
	ln -sf cc_mode/guestos.pb-c.c guestos.pb-c.c
	ln -sf cc_mode/guestos.pb-c.h guestos.pb-c.h
	ln -sf cc_mode/device.pb-c.c device.pb-c.c
	ln -sf cc_mode/device.pb-c.h device.pb-c.h
	protoc-c --c_out=. control.proto
	protoc-c --c_out=. scd.proto
	protoc-c --c_out=. attestation.proto
	protoc-c --c_out=. tpm2d.proto
	protoc-c --c_out=. c_service.proto
	$(MAKE) -C common protobuf

else
protobuf: container.proto control.proto guestos.proto device.proto scd.proto common/audit.proto c_service.proto oci_control.proto
	protoc-c --c_out=. container.proto
	protoc-c --c_out=. control.proto
	protoc-c --c_out=. guestos.proto
	protoc-c --c_out=. device.proto
	protoc-c --c_out=. scd.proto
	protoc-c --c_out=. attestation.proto
	protoc-c --c_out=. tpm2d.proto
	protoc-c --c_out=. c_service.proto
	protoc-c --c_out=. oci_control.proto
	$(MAKE) -C common protobuf

endif

$(PROTO_SRC): protobuf

libcommon:
	$(MAKE) -C common libcommon_full WITH_PROTOBUF_TEXT=y

cmld: libcommon $(PROTO_SRC) $(SRC_FILES) $(SRC_CMODULES)
	$(CC) $(LOCAL_CFLAGS) $(SRC_FILES) $(SRC_CMODULES) $(PROTO_SRC) $(LDLIBS) -o cmld


.PHONY: clean
clean:
	rm -f cmld *.o *.pb-c.*
	$(MAKE) -C common clean
