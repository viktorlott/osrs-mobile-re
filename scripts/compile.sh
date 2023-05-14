#!/bin/bash

# Service name:
# com.company.subcategory.platform
# ^^^ ^^^^^^^ ^^^^^^^^^^^ ^^^^^^^^
SERVICE=com.myosrs.oldscape.android

SDK_DIR=~/Library/Android/sdk/build-tools/33.0.2

TOOLS_DIR=./tools
SOURCE_DIR=./apps
TARGET_DIR=./target
SCRIPTS_DIR=./scripts

APK_NAME=osrs-app

KEYSTORE=./ghidra/debug.keystore

SCRIPT_NAME=device-script.js

export ANDROID_SERIAL=emulator-5554



echo -e "\033[36mCompile the decompiled source:\033[0m"
java -jar $TOOLS_DIR/apktool_2.7.0.jar b "$SOURCE_DIR/$APK_NAME" -o "$TARGET_DIR/$APK_NAME.apk"

echo -e "\033[36mSign and verify the newly compiled apk:\033[0m"
$SDK_DIR/apksigner sign --verbose --ks-pass pass:android --ks $KEYSTORE "$TARGET_DIR/$APK_NAME.apk"
$SDK_DIR/apksigner verify --verbose "$TARGET_DIR/$APK_NAME.apk"

if [ "$(adb -s emulator-5554 shell getprop > /dev/null 2>&1)" \
 = "adb: device 'emulator-5554' not found" ]; then
  echo -e "\033[31mDevice not found\033[0m" 
  exit 0
fi

echo -e "\033[36mStop app if it's running in the emulator:\033[0m"
adb -s emulator-5554 shell am force-stop com.myosrs.oldscape.android 
echo "Done"

# adb uninstall com.example.myapp

echo -e "\033[36mInstall the signed compiled apk in the emulator:\033[0m"
adb -s emulator-5554 install ./$TARGET_DIR/$APK_NAME.apk

# echo -e "\033[36mPushing frida script to device:\033[0m"
# adb push $SCRIPTS_DIR/$SCRIPT_NAME /data/local/tmp
# adb shell chmod 777 /data/local/tmp/$SCRIPT_NAME

# echo -e "\033[36mSet the apk app to debug mode:\033[0m"
# adb -s emulator-5554 shell am set-debug-app -w com.myosrs.oldscape.android

echo -e "\033[36mStart the apk that we have installed:\033[0m"
adb -s emulator-5554 shell monkey -p com.myosrs.oldscape.android 1
echo -e "\033[36mDONE!\033[0m"

# adb logcat -s "myrsos-log:V" | logcat-colorize


