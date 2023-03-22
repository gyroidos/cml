#
# This file is part of GyroidOS
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
# Fraunhofer AISEC <gyroidos@aisec.fraunhofer.de>
#

LOCAL_PATH:= $(call my-dir)

CMLD_COMMON_CFLAGS := -pedantic -Wall -Wextra -Werror -std=c99

CMLD_COMMON_SRC_FILES := \
	common/list.c \
	common/logf.c \
	common/mem.c

include $(CLEAR_VARS)

LOCAL_MODULE := cml-control
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := $(CMLD_COMMON_SRC_FILES) \
	common/protobuf.c \
	common/sock.c \
	common/file.c \
	common/fd.c \
	control.proto \
	common/logf.proto \
	guestos.proto \
	container.proto \
	control.c

LOCAL_STATIC_LIBRARIES += libprotobuf-c-text libc

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

