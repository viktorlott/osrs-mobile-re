#!/bin/bash

SDK_DIR=/Users/ViktorL/Library/Android/sdk/build-tools/33.0.2

# Service name:
# com.company.subcategory.platform
# ^^^ ^^^^^^^ ^^^^^^^^^^^ ^^^^^^^^
SERVICE=com.myosrs.oldscape.android

SOURCE_DIRECTORY=/Users/ViktorL/Downloads
SOURCE_TARGET="Old School RuneScape_213.2_Apkpure"

export ANDROID_SERIAL=emulator-5554

echo -e "\033[36mCompile the decompiled source:\033[0m"
java -jar $SOURCE_DIRECTORY/apktool_2.7.0.jar b "$SOURCE_DIRECTORY/$SOURCE_TARGET" -o "$SOURCE_DIRECTORY/$SOURCE_TARGET.apk"

echo -e "\033[36mSign and verify the newly compiled apk:\033[0m"
$SDK_DIR/apksigner sign --verbose --ks-pass pass:android --ks $SOURCE_DIRECTORY/debug.keystore "$SOURCE_DIRECTORY/$SOURCE_TARGET.apk"
$SDK_DIR/apksigner verify --verbose "$SOURCE_DIRECTORY/$SOURCE_TARGET.apk"

if [ "$(adb -s emulator-5554 shell getprop > /dev/null 2>&1)" = "adb: device 'emulator-5554' not found" ]; then
  echo -e "\033[31mDevice not found\033[0m" 
  exit 0
fi

echo -e "\033[36mStop app if it's running in the emulator:\033[0m"
adb -s emulator-5554 shell am force-stop com.myosrs.oldscape.android 
echo "Done"

# adb uninstall com.example.myapp

echo -e "\033[36mInstall the signed compiled apk in the emulator:\033[0m"
adb -s emulator-5554 install /Users/ViktorL/Downloads/Old\ School\ RuneScape_213.2_Apkpure.apk

# echo -e "\033[36mSet the apk app to debug mode:\033[0m"
# adb -s emulator-5554 shell am set-debug-app -w com.myosrs.oldscape.android

echo -e "\033[36mStart the apk that we have installed:\033[0m"
adb -s emulator-5554 shell monkey -p com.myosrs.oldscape.android 1


