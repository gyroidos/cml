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
include $(CLEAR_VARS)

LOCAL_MODULE := converter
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := \
	common/protobuf.c \
	common/logf.c \
	common/dir.c \
	common/file.c \
	common/list.c \
	common/mem.c \
	common/fd.c \
	cJSON/cJSON.c \
	guestos.proto \
	util.c \
	docker.c \
	converter.c

LOCAL_STATIC_LIBRARIES := \
	libprotobuf-c-text \
	libselinux \
	libz \
	libminitar \
	libtar \
	liblog \
	libmincrypt \
	libcutils \
	libc

LOCAL_C_INCLUDES += \
	external/libtar \
	external/libtar/lib \
	external/libtar/listhash

LOCAL_CFLAGS += -pedantic -Wall -Wextra -Werror -std=c99

ifneq (,$(filter userdebug eng,$(TARGET_BUILD_VARIANT)))
LOCAL_CFLAGS += -DDEBUG_BUILD
endif

LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT_SBIN)
LOCAL_UNSTRIPPED_PATH := $(TARGET_ROOT_OUT_SBIN_UNSTRIPPED)

LOCAL_MODULE_CLASS := EXECUTABLES
include external/protobuf-c/prepare-protoc-build.mk
include $(BUILD_EXECUTABLE)

#########################
include $(CLEAR_VARS)

LOCAL_MODULE := converter_host
LOCAL_MODULE_STEM := converter
LOCAL_MODULE_TAGS := optional

LOCAL_SRC_FILES := \
	common/logf.c \
	common/dir.c \
	common/file.c \
	common/list.c \
	common/mem.c \
	common/fd.c \
	common/protobuf.c \
	cJSON/cJSON.c \
	guestos.proto \
	util.c \
	docker.c \
	converter.c \

LOCAL_STATIC_LIBRARIES := \
	libprotobuf-c-text-host \
	libunz \
	libtar \
	liblog \
	libmincrypt \
	libselinux_full_host \
	libcutils

LOCAL_WHOLE_STATIC_LIBRARIES := \
	libminitar

LOCAL_C_INCLUDES += \
	external/libtar \
	external/libtar/lib \
	external/libtar/listhash

LOCAL_CFLAGS := -pedantic -Wall -Wextra -Werror -UANDROID -Wno-error=unused-parameter -std=gnu99
LOCAL_LDFLAGS := -lresolv

ifneq (,$(filter userdebug eng,$(TARGET_BUILD_VARIANT)))
LOCAL_CFLAGS += -DDEBUG_BUILD
endif
LOCAL_FORCE_STATIC_EXECUTABLE := true

LOCAL_MODULE_CLASS := EXECUTABLES

include external/protobuf-c/prepare-protoc-build-host.mk

include $(BUILD_HOST_EXECUTABLE)
