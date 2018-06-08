#
# This file is part of trust|me
# Copyright(c) 2013 - 2017 Fraunhofer AISEC
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

LOCAL_PATH:= $(call my-dir)

PLATFORM_VERSION_MAJOR = $(shell echo $(PLATFORM_VERSION) | cut -f1 -d.)

CMLD_COMMON_CFLAGS := -pedantic -Wall -Wextra -Werror -std=c99 \
	-DPLATFORM_VERSION_MAJOR=$(PLATFORM_VERSION_MAJOR)

CMLD_COMMON_SRC_FILES := \
	common/reboot.c \
	common/list.c \
	common/logf.c \
	common/mem.c

# Define common cflags and src files for unit tests
CMLD_COMMON_TEST_CFLAGS := $(CMLD_COMMON_CFLAGS) \
	-include common/utest.h

CMLD_COMMON_TEST_SRC_FILES := $(CMLD_COMMON_SRC_FILES) \
	common/utest.c


include $(CLEAR_VARS)

LOCAL_MODULE := trustme.cml.uuid.test.host
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := $(CMLD_COMMON_TEST_SRC_FILES) \
	common/uuid.c \
	common/uuid.test.c

LOCAL_CFLAGS += $(CMLD_COMMON_TEST_CFLAGS)

ifneq (,$(filter userdebug eng,$(TARGET_BUILD_VARIANT)))
LOCAL_CFLAGS += -DDEBUG_BUILD
endif

include $(BUILD_HOST_EXECUTABLE)


include $(CLEAR_VARS)

LOCAL_MODULE := trustme.cml.container.test
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := $(CMLD_COMMON_SRC_FILES) \
	common/sock.c \
	common/event.c \
	common/str.c \
	common/uuid.c \
	common/file.c \
	common/fd.c \
	common/loopdev.c \
	common/cryptfs.c \
	common/protobuf.c \
	common/dir.c \
	common/nl.c \
	common/proc.c \
	container.c \
	c_cgroups.c \
	container.proto \
	container_config.c \
	c_net.c \
	c_service.c \
	c_service.proto \
	c_vol.c \
	c_cap.c \
	crypto.proto \
	guestos.proto \
	guestos.c \
	guestos_config.c \
	guestos_mgr.c \
	hw_$(TRUSTME_HARDWARE)-$(PLATFORM_VERSION).c \
	display.c \
	smartcard.c \
	cmld.c \
	mount.c \
	container.test.c

LOCAL_STATIC_LIBRARIES := \
	libc \
	libcutils \
	liblog \
	libprotobuf-c-text

LOCAL_CFLAGS += $(CMLD_COMMON_CFLAGS)

ifneq (,$(filter userdebug eng,$(TARGET_BUILD_VARIANT)))
LOCAL_CFLAGS += -DDEBUG_BUILD
endif

LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT_SBIN)
LOCAL_UNSTRIPPED_PATH := $(TARGET_ROOT_OUT_SBIN_UNSTRIPPED)

LOCAL_MODULE_CLASS := EXECUTABLES
include external/protobuf-c/prepare-protoc-build.mk

include $(BUILD_EXECUTABLE)


include $(CLEAR_VARS)

LOCAL_MODULE := cml-daemon
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := $(CMLD_COMMON_SRC_FILES) \
	common/sock.c \
	common/event.c \
	common/str.c \
	common/uuid.c \
	common/file.c \
	common/fd.c \
	common/nl.c \
	common/loopdev.c \
	common/cryptfs.c \
	common/protobuf.c \
	common/dir.c \
	common/network.c \
	common/proc.c \
	container.c \
	c_cgroups.c \
	container.proto \
	container_config.c \
	c_net.c \
	c_service.c \
	c_service.proto \
	c_vol.c \
	c_cap.c \
	scd.proto \
	control.proto \
	common/logf.proto \
	guestos.proto \
	control.c \
	power.c \
	hw_$(TRUSTME_HARDWARE)-$(PLATFORM_VERSION).c \
	display.c \
	crypto.proto \
	guestos.c \
	guestos_config.c \
	guestos_mgr.c \
	download.c \
	device_config.c \
	device.proto \
	mount.c \
	ksm.c \
	smartcard.c \
	cmld.c \
	main.c

LOCAL_STATIC_LIBRARIES := \
	libc \
	libcutils \
	liblog \
	libprotobuf-c-text \
	libselinux

LOCAL_CFLAGS += $(CMLD_COMMON_CFLAGS)

ifneq (,$(filter userdebug eng,$(TARGET_BUILD_VARIANT)))
LOCAL_CFLAGS += -DDEBUG_BUILD

#LOCAL_STRIP_MODULE := false
LOCAL_STRIP_MODULE := keep_symbols
LOCAL_CFLAGS += -g # debug symbols; adds dwarf stack unwind information as .debug_frame section

# prevents compiler from optimizing frame pointer away which sometimes is needed for stack unwinding
#LOCAL_CFLAGS += -fno-omit-frame-pointer

# .ARM.exidx and .ARM.extab. frame unwinding information (not yet supported by perf...)
#LOCAL_CFLAGS += -funwind-tables -fasynchronous-unwind-tables
endif

LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT_SBIN)
LOCAL_UNSTRIPPED_PATH := $(TARGET_ROOT_OUT_SBIN_UNSTRIPPED)

LOCAL_MODULE_CLASS := EXECUTABLES
include external/protobuf-c/prepare-protoc-build.mk

include $(BUILD_EXECUTABLE)


# Java protobuf library for TrustmeService
include $(CLEAR_VARS)
LOCAL_MODULE := trustme.cml.service-proto-java
LOCAL_MODULE_TAGS := optional
LOCAL_SDK_VERSION := 8
LOCAL_PROTOC_OPTIMIZE_TYPE := nano
LOCAL_PROTOC_FLAGS := --proto_path=$(LOCAL_PATH)
#LOCAL_PROTO_JAVA_OUTPUT_PARAMS := optional_field_style=accessors
#LOCAL_PROTO_JAVA_OUTPUT_PARAMS := java_nano_generate_has=true
LOCAL_SRC_FILES := c_service.proto container.proto
include $(BUILD_STATIC_JAVA_LIBRARY)


include $(CLEAR_VARS)

LOCAL_MODULE := trustme.cml.control.test
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := $(CMLD_COMMON_SRC_FILES) \
	common/event.c \
	common/uuid.c \
	common/str.c \
	common/sock.c \
	common/protobuf.c \
	common/fd.c \
	common/file.c \
	container.stub.c \
	cmld.stub.c \
	hardware.stub.c \
	guestos.stub.c \
	control.proto \
	common/logf.proto \
	guestos.proto \
	container.proto \
	control.test.c

LOCAL_STATIC_LIBRARIES += libprotobuf-c-text libc

LOCAL_CFLAGS += $(CMLD_COMMON_CFLAGS)

ifneq (,$(filter userdebug eng,$(TARGET_BUILD_VARIANT)))
LOCAL_CFLAGS += -DDEBUG_BUILD
endif

LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_MODULE_CLASS := EXECUTABLES
include external/protobuf-c/prepare-protoc-build.mk

LOCAL_MODULE_CLASS := EXECUTABLES
include external/protobuf-c/prepare-protoc-build.mk
include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)


### c_net Unit Test
### c_net.c is included by c_net.test.c
LOCAL_MODULE := trustme.cml.c_net.test
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := $(CMLD_COMMON_SRC_FILES) \
	common/nl.c \
	common/uuid.c \
	common/fd.c \
	common/file.c \
	common/network.c \
	container.stub.c \
	c_net.test.c

LOCAL_WHOLE_STATIC_LIBRARIES := libc

LOCAL_CFLAGS := -DDEBUG_BUILD -std=c99

LOCAL_FORCE_STATIC_EXECUTABLE := true
include $(BUILD_EXECUTABLE)
###

# control.srv for testing only
#include $(CLEAR_VARS)
#
#LOCAL_MODULE := trustme.cml.control.srv
#LOCAL_MODULE_TAGS := optional
#LOCAL_SRC_FILES := $(CMLD_COMMON_SRC_FILES) \
#	common/event.c \
#	common/uuid.c \
#	common/str.c \
#	common/sock.c \
#	common/protobuf.c \
#	common/fd.c \
#	container.stub.c \
#	cmld.stub.c \
#	guestos.stub.c \
#	control.proto \
#	control.srv.c
#
#LOCAL_STATIC_LIBRARIES += libprotobuf-c-text libc
#
#LOCAL_CFLAGS += $(CMLD_COMMON_CFLAGS)
#
#ifneq (,$(filter userdebug eng,$(TARGET_BUILD_VARIANT)))
#LOCAL_CFLAGS += -DDEBUG_BUILD
#endif
#
#LOCAL_FORCE_STATIC_EXECUTABLE := true
#
#LOCAL_MODULE_CLASS := EXECUTABLES
#include external/protobuf-c/prepare-protoc-build.mk
#include $(BUILD_EXECUTABLE)

# Java protobuf library for TrustmeLauncher
include $(CLEAR_VARS)
LOCAL_MODULE := trustme.cml.control-proto-java
LOCAL_MODULE_TAGS := optional
LOCAL_SDK_VERSION := 8
LOCAL_PROTOC_OPTIMIZE_TYPE := nano
LOCAL_PROTOC_FLAGS := --proto_path=$(LOCAL_PATH)
LOCAL_SRC_FILES := control.proto \
	common/logf.proto \
	guestos.proto \
	container.proto
include $(BUILD_STATIC_JAVA_LIBRARY)

