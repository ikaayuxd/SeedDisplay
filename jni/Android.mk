LOCAL_PATH := $(call my-dir)

# ── libBedrockTools (prebuilt) ────────────────────────────────────────────────
include $(CLEAR_VARS)
LOCAL_MODULE            := BedrockTools
LOCAL_SRC_FILES         := libs/arm64-v8a/libBedrockTools.so
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/include
include $(PREBUILT_SHARED_LIBRARY)

# ── ImGui (compiled from source) ─────────────────────────────────────────────
include $(CLEAR_VARS)
LOCAL_MODULE     := imgui
LOCAL_SRC_FILES  := \
    imgui/imgui.cpp             \
    imgui/imgui_draw.cpp        \
    imgui/imgui_tables.cpp      \
    imgui/imgui_widgets.cpp     \
    imgui/imgui_impl_opengl3.cpp \
    imgui/imgui_impl_android.cpp
LOCAL_C_INCLUDES := $(LOCAL_PATH)/imgui
LOCAL_CPPFLAGS   := -std=c++17 -O2
include $(BUILD_STATIC_LIBRARY)

# ── SeedDisplay ───────────────────────────────────────────────────────────────
include $(CLEAR_VARS)
LOCAL_MODULE        := SeedDisplay
LOCAL_SRC_FILES     := main.cpp
LOCAL_C_INCLUDES    := \
    $(LOCAL_PATH)/include \
    $(LOCAL_PATH)/imgui

LOCAL_CPPFLAGS         := -std=c++17 -O2 -fvisibility=hidden -fexceptions -frtti
LOCAL_LDLIBS           := -llog -lEGL -lGLESv3 -landroid
LOCAL_STATIC_LIBRARIES := imgui
LOCAL_SHARED_LIBRARIES := BedrockTools

include $(BUILD_SHARED_LIBRARY)
