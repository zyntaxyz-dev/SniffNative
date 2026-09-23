THEOS_DEVICE_IP = 127.0.0.1
ARCHS = arm64 arm64e
TARGET = iphone:clang:latest:15.0

TWEAK_NAME = SniffNative
SniffNative_FILES = Tweak.x
SniffNative_CFLAGS = -fobjc-arc -Wno-deprecated-declarations

include $(THEOS)/makefiles/common.mk
include $(THEOS_MAKE_PATH)/tweak.mk
