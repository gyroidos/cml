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

include $(CLEAR_VARS)

LOCAL_MODULE := cml-scd
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := \
	common/list.c \
	common/logf.c \
	common/mem.c \
	common/sock.c \
	common/event.c \
	common/str.c \
	common/file.c \
	common/dir.c \
	common/fd.c \
	common/uuid.c \
	common/protobuf.c \
	common/reboot.c \
	common/ssl_util.c \
	scd.proto \
	device.proto \
	control.c \
	softtoken.c \
	scd.c

ifeq ($(shell test $(PLATFORM_VERSION_MAJOR) -gt 5; echo $$?),0)

LOCAL_STATIC_LIBRARIES := \
	libprotobuf-c-text \
	libcutils \
	openssl_libcrypto_static \
	liblog \
	libdl-static \
	libc

LOCAL_C_INCLUDES := \
	external/openssl_legacy/include
else

LOCAL_STATIC_LIBRARIES := \
	libprotobuf-c-text \
	libcutils \
	libcrypto_static \
	liblog \
	libdl-static \
	libc

LOCAL_C_INCLUDES := \
	external/openssl/include
endif


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

include $(CLEAR_VARS)
LOCAL_MODULE := keyrewrap-scd
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := \
	common/utest.c \
	common/list.c \
	common/logf.c \
	common/mem.c \
	common/str.c \
	common/file.c \
	common/fd.c \
	common/ssl_util.c \
	softtoken.c \
	keyrewrap.c

LOCAL_SHARED_LIBRARIES := \
	libcrypto-host

LOCAL_C_INCLUDES := \
		    external/openssl_legacy/include

LOCAL_CFLAGS += -include common/utest.h
LOCAL_CFLAGS += -pedantic -Wall -Wextra -Werror -std=gnu99
#LOCAL_CFLAGS += -D_GNU_SOURCE -D_POSIX_C_SOURCE

LOCAL_MODULE_CLASS := EXECUTABLES

include $(BUILD_HOST_EXECUTABLE)
