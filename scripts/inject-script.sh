#!/bin/bash

# Push this cool script to our emulator
adb push device-script.js /data/local/tmp
adb shell chmod 777 /data/local/tmp/device-script.js

adb logcat -s "myrsos-log:V"