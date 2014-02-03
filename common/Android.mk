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

PLATFORM_VERSION_MAJOR := $(shell echo $(PLATFORM_VERSION) | cut -f1 -d.)

COMMON_CFLAGS += -DPLATFORM_VERSION_MAJOR=$(PLATFORM_VERSION_MAJOR)

include $(CLEAR_VARS)
LOCAL_MODULE := trustme.cml.libcommon
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := \
	event.c \
	list.c \
	logf.c \
	mem.c \
	str.c \
	nl.c

LOCAL_C_INCLUDES := $(LOCAL_PATH)/../include

LOCAL_CFLAGS += $(COMMON_CFLAGS)
LOCAL_CFLAGS += -pedantic -Wall -Wextra -Werror -std=c99

LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)

ifneq (,$(filter userdebug eng,$(TARGET_BUILD_VARIANT)))
LOCAL_CFLAGS += -DDEBUG_BUILD
endif

LOCAL_WHOLE_STATIC_LIBRARIES := \
	libcutils \
	liblog \
	libc

include $(BUILD_STATIC_LIBRARY)


#########################
# Unit Test Targets     #
#########################
# str.c
include $(CLEAR_VARS)

LOCAL_MODULE := trustme.cml.common.str.test
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := \
	list.c \
	logf.c \
	mem.c \
	str.c \
	str.test.c

LOCAL_CFLAGS += $(COMMON_CFLAGS)
LOCAL_CFLAGS += -DDEBUG_BUILD -std=c99

LOCAL_WHOLE_STATIC_LIBRARIES := \
	libc \

LOCAL_FORCE_STATIC_EXECUTABLE := true
include $(BUILD_EXECUTABLE)

#########################
# event.c
include $(CLEAR_VARS)

LOCAL_MODULE := trustme.cml.common.event.test
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := \
	logf.c \
	mem.c \
	list.c \
	event.c \
	event.test.c

LOCAL_CFLAGS += $(COMMON_CFLAGS)
LOCAL_CFLAGS += -DDEBUG_BUILD -std=c99

LOCAL_WHOLE_STATIC_LIBRARIES := \
	libc

LOCAL_FORCE_STATIC_EXECUTABLE := true
include $(BUILD_EXECUTABLE)

#########################
# list.c
include $(CLEAR_VARS)

LOCAL_MODULE := trustme.cml.common.list.test
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := \
	mem.c \
	logf.c \
	list.c \
	list.test.c

LOCAL_WHOLE_STATIC_LIBRARIES := \
	libc

LOCAL_CFLAGS += $(COMMON_CFLAGS)
LOCAL_CFLAGS += -DDEBUG_BUILD -std=c99

LOCAL_FORCE_STATIC_EXECUTABLE := true
include $(BUILD_EXECUTABLE)

#########################
# logf.c
include $(CLEAR_VARS)

LOCAL_MODULE := trustme.cml.common.logf.test
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := \
	mem.c \
	list.c \
	logf.c \
	logf.test.c

LOCAL_CFLAGS += $(COMMON_CFLAGS)
LOCAL_CFLAGS += -DDEBUG_BUILD -std=c99

LOCAL_WHOLE_STATIC_LIBRARIES := \
	libc

LOCAL_FORCE_STATIC_EXECUTABLE := true
include $(BUILD_EXECUTABLE)

#########################
# mem.c
include $(CLEAR_VARS)

LOCAL_MODULE := trustme.cml.common.mem.test
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := \
	mem.c \
	logf.c \
	list.c \
	mem.test.c

LOCAL_CFLAGS += $(COMMON_CFLAGS)
LOCAL_CFLAGS += -DDEBUG_BUILD -std=c99

LOCAL_WHOLE_STATIC_LIBRARIES := \
	libc

LOCAL_FORCE_STATIC_EXECUTABLE := true
include $(BUILD_EXECUTABLE)

#########################
# nl.c
# nl.c is included in nl.test.c in order be able to debug structs
include $(CLEAR_VARS)

LOCAL_MODULE := trustme.cml.common.nl.test.host
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := mem.c \
		   utest.c \
		   logf.c \
		   list.c \
		   nl.test.c

LOCAL_C_INCLUDES := $(LOCAL_PATH)/../include

LOCAL_CFLAGS += $(COMMON_CFLAGS)
LOCAL_CFLAGS += -include utest.h -DDEBUG_BUILD -std=c99

LOCAL_MODULE_CLASS := EXECUTABLES

include $(BUILD_HOST_EXECUTABLE)
