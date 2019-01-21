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

tss_cflags := \
	-Wall -W -Wmissing-declarations -Wmissing-prototypes -Wnested-externs \
	-ggdb -O0 -c \
	-DTPM_ENCRYPT_SESSIONS_DEFAULT="\"0\"" \
	-DTPM_TPM20 \
	-DTPM_POSIX

LOCAL_MODULE := cml-tpm2d
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := \
	common/list.c \
	common/logf.c \
	common/mem.c \
	common/sock.c \
	common/event.c \
	common/dir.c \
	common/file.c \
	common/fd.c \
	common/protobuf.c \
	common/cryptfs.c \
	tpm2d.proto \
	control.c \
	tpm2_commands.c \
	nvmcrypt.c \
	ml.c \
	ek.c \
	tpm2d.c \

LOCAL_WHOLE_STATIC_LIBRARIES := \
	libibmtss

LOCAL_STATIC_LIBRARIES := \
	libprotobuf-c-text \
	openssl_libcrypto_static \
	libcutils \
	liblog \
	libdl-static \
	libc
#	npa

LOCAL_CFLAGS += -std=c99 -Wextra -Werror $(tss_cflags)

ifneq (,$(filter userdebug eng,$(TARGET_BUILD_VARIANT)))
LOCAL_CFLAGS += -DDEBUG_BUILD
endif

LOCAL_C_INCLUDES += \
	external/ibmtpm20tss/utils \
	external/openssl_legacy/include

LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT_SBIN)
LOCAL_UNSTRIPPED_PATH := $(TARGET_ROOT_OUT_SBIN_UNSTRIPPED)

LOCAL_MODULE_CLASS := EXECUTABLES
include external/protobuf-c/prepare-protoc-build.mk
include $(BUILD_EXECUTABLE)
