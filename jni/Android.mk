LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE            := BedrockTools
LOCAL_SRC_FILES         := libs/arm64-v8a/libBedrockTools.so
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/include
include $(PREBUILT_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE        := SeedDisplay
LOCAL_SRC_FILES     := main.cpp
LOCAL_C_INCLUDES    := \
    $(LOCAL_PATH)/include \
    $(LOCAL_PATH)/imgui

LOCAL_CPPFLAGS         := -std=c++17 -O2 -fvisibility=hidden -fexceptions -frtti
LOCAL_LDLIBS           := -llog -lEGL -lGLESv3 -landroid
LOCAL_SHARED_LIBRARIES := BedrockTools

include $(BUILD_SHARED_LIBRARY)
