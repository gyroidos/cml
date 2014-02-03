LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := cml-logcat
LOCAL_MODULE_TAGS := optional
#LOCAL_PRELINK_MODULE := false
#LOCAL_MODULE_CLASS := EXECUTABLES

LOCAL_SRC_FILES := \
	logcat/logcat.cpp \
	liblog/event_tag_map.c \
	liblog/logprint.c

LOCAL_C_INCLUDES := $(LOCAL_PATH)/include

LOCAL_STATIC_LIBRARIES := \
	libstdc++ \
	libc 

LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT_SBIN)
LOCAL_UNSTRIPPED_PATH := $(TARGET_ROOT_OUT_SBIN_UNSTRIPPED)

include $(BUILD_EXECUTABLE)


