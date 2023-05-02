# Manipulating the OSRS Native Android mobile app.

## UNDER DEVELOPMENT

### Goal
Build a working wrapping for tracking internal game state. 
> Currently I'm keeping everything relating to the apk local.


## Tools
- Java 8/11
- Android studio - IDE for android apps (Optional)
- Android build tools
  - apksigner - Used to sign the recompiled apk
  - emulator - A tool for instantiating an emulator
  - adb - Interact with the emulator
- Ghidra - Used to decode the binary (Reverse engineering tool)
- apktool - Used for de/re-compilation
- jadx - Used to convert a apk to readable java code
- Hex editor - Used to edit the binary (I use Hex Fiend on mac)
- dex2jar - Apk tools (Optional)


## Concepts
- Android NDT and JNI
- Shared object
- Dalvik bytecode (smali)


## Things I've discovered.
The OSRS Android app is developed either as Phone Native c++ or Game
Activity c++ project. Though it might just be a port from the RS3 NXT
engine, meaning that they might have just ported the game engine and
then added a android native wrapper on top of it. There would then be
the normal JNI and NDK wrapper, followed by the JavaMobileWrapper.

The NDK works by binding the native code to Android, such that they can
call every Java class from Native code. The JNI lets Java call native
functions inside the bianry.

By analysing the .so with Ghidra, and attaching the jni.h file to the
data type manager, I've discover a lot more things about the actual
binary. For example, it uses the NDK to natively attach it self to the
touch event listener and then concurrenly polls events from the event
queue, without involving the top java wrapper. I'm pretty new at this, 
but that took me a while to understand. If one inspect the Android Manifest,
one could see under `<Application>` `<activity android:configChanges=".." >` 
that it uses `touchscreen` such that changes to the touchscreen can be
handled (or intercepted) by the binary (OBS, this is not the same as
regular touch events).

One thing that I still want to explore it that the binary
still needs to bind the Android NativeActivity class, so if I were to
inject or override the class, I could potentially intercept all actions
being made.

Network... (TODO)


Shaders... (TODO)

> The GL shader definitions are for sure present in the binary.

## Steps
1. Download the OSRS apk somewhere (I'm not allowed to link it here)
2. TODO..

  