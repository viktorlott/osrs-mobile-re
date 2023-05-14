# OSRS Native Android mobile app

> This is a project that is still under development

This project aims to reverse engineer the OSRS mobile app to build a
working wrapper for tracking the internal game state. It provides a
"detailed" learning journey into the world of reverse engineering (RE).
It's cool to learn fun shit.

## Goals
- Explore and learn RE techniques.
- Maintain thorough documentation of the project.
- Develop a working wrapper for tracking internal game state.

## Terminologies
Familiarity with the following terms is essential for understanding this project:
- ARM ISA
- Linux kernel
- Android OS
- Android NDT, JNI and AGDK
- Dalvik VM and ART (Android runtime) 
- Android Java bytecode (smali)
- Dalvik Executable (.dex files)
- ELF and Shared object (.so)

## Tools
| Name           | Description                                          | Required |
|:---------------|:-----------------------------------------------------|:--------:|
| Android studio | IDE for android apps                                 |          |
| Java 8/11      | JDK                                                  |          |
| apksigner      | Used to sign the recompiled apk                      |    X     |
| emulator       | The Android emulator that will run the modified apk  |    X     |
| adb            | Interact with the emulator                           |    X     |
| Ghidra         | Used to decode the binary (Reverse engineering tool) |          |
| jadx           | Used to convert a apk to readable java code          |          |
| dextools       | Dalvik executable tools                              |          |
| Hex editor     | Used to edit the binary (I use Hex Fiend on mac)     |          |
| apktool        | Used for de/re-compilation                           |    X     |
| frida-tools    | RE tool for runtime analysis                         |    X     |
| LIEF           | Library to instrument executable formats             |          |
| QBDI           | Dyn bin instrumentation                              |          |


## Disassembling and Decompiling
In this section, we delve into RE techniques and best practices. Include
header files from NDK, AGDK, and Android from the following locations:
- Include header files from NDK, AGDK and Android.
  - *android-ndk-r25c/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/include*
  - *android-ndk-r25c/prebuilt/linux-x86_64/include*
  - *android-ndk-r25c/sources*
  - *Java/JavaVirtualMachines/jdk-20.jdk/Contents/Home/include*

## Formats
- .a files   - Archive libraries are statically linked
- .so files  - Shared objects are dynamically linked
- .oat files - Statically compiled odex
- .dex       - Dalvik executable

## Project structure
- source/*.apk    - The apk that will be edited 
- apps/*          - The decompiled apk
- target/*.apk    - The recompiled apk
- frida/*         - The frida injection tools


## Did you know..
- Dalvik/ART VM uses a register-based architecture (register machine),
  while JVM uses stack-based architecture (stack machines).

- ART (Anroid Runtime) replaced Dalvik VM in Android Lollipop version.
  
- ART uses AOT (Ahead-of-time) compilation.
  - It also has a JIT compiler, so the AOT and JIT complement eachother.
  
- DVM uses JIT (Just-in-time) compilation.

- JIT lets Android dynamically compile an app by interpreting a .dex
  file and then compiling it into executable code during runtime.

- AOT lets Android statically compile a .dex (into a .oat file), which
  then can be stored on the device and executed at any time without
  having to reinterprete and JIT compile it every time the app is
  launched.

- Profile-guided compilations is a technique that ART can use to
  increase app performance.

- Android apps are first compiled into Java bytecode, then into Dalvik
  bytcode.

- The smali format is a human-readable Dex bytecode.

- JNI (Java Native Interface) bindings are used by the Dalvik/ART VM to
  call native functions in binaries, and vise versa. 

- NDK (Native Development Kit) is a toolkit that allows developers to
  write native code to interface with Dalvik/ART VM through JNI.

- AGDK (Android Game Development Kit) is a toolkit which contains
  libraries that assists the developer in writing Android games in
  native code. It can also interface with the Dalvik/ART VM because it
  also uses NDK and JNI. Note that it does not always need to use them
  because AGDK contains libraries that can interact independent of JNI.


## The story so far
By analysing the .so with **Ghidra**, and attaching the jni.h file to
the data type manager, I've discover a lot more things about the actual
binary. For example, it uses the NDK to natively attach it self to the
touch event listener and then concurrency polls events from the event
queue, without involving the top java wrapper. I'm pretty new at this,
but that took me a while to understand. If one inspect the Android
Manifest, one could see under 
`<Application>` `<activity android:configChanges=".." >` 
that it uses `touchscreen` such that changes to the touchscreen can be
handled (or intercepted) by the binary (OBS, this is not the same as
regular touch events).

One thing that I still want to explore is the Android NativeActivity
class bindings. If I were to inject or override the class, I could
potentially intercept all actions being made. This could either be done
under compile-time, or during runtime with tools like **frida**. 


<img src="/picofart.png" style="height: 400px;" />

**TODO subjects**
Network...
Shaders...
Protect against .apk tampering...
DexGuard...
Debugging...

### Frida
Using frida with signed apks on jailed android is a bit tricky. We
cannot just use the regualar old **frida-server** and attach it to the
process. Instead we need to use the **frida-gadget**. This requires us
to insert a binary (called a gadget) into the apk (next to the other
binary), and then call system.loadlibrary in Java. The thing is that our
disassembled apk doesn't contain any real Java code, it contains dex
decompiled bytecode that has been translated into smali format,
human-readable Dalvik bytecode. 

> When inserting the frida-gadget into the apk, make sure the name
> of the binary is prefixed with `lib` and suffixed in `.so`. Make sure
> that the loadLibrary call take place before it loads in the next
> library.

#### Random notes
The OSRS Android app seems to be developed either as an Android Native c++, Game
Activity c++ project, or a port from the RS3 NXT engine - meaning that
they might have ported the game engine and then added a android native
wrapper on top of it. 

> The JNI bindings are used in both projects, but it's never automatically
> added to Game Activity c++ projects (except for the AGDK parts). What I
> mean is that there's no `stringFromJNI` native method example present in
> GA, like there is in the Android Native c++ project. 
#### Loading so files
Injecting into smali.
```smali
const-string v0, "abc"
invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
```
or use LIEF to inject the dylib directly into osrs lib binary

## Steps to Get Started

1. **Download the OSRS APK:** The first step is to download the OSRS apk
   file. Due to legal reasons, we can't provide a direct link here, but
   you can easily find it on the official app store or an APK
   repository.

2. **Decompile the APK:** Use JADX or apktool to decompile the APK into
   readable code.
   ```sh
   java -jar /path/to/apktool_2.7.0.jar d app.apk -o /path/to/folder
   ```

3. **Analyze the Decompiled Code:** Explore the decompiled APK to
   understand its structure and operation. Look for any interesting
   methods or classes that could be used or modified for your purposes.

4. **Inject Frida Gadget:** Inject the Frida Gadget into the APK. This
   will allow for runtime analysis and manipulation of the app. Ensure
   that the gadget is correctly named (prefixed with `lib` and suffixed
   with `.so`) and that the `loadLibrary` call is made before loading
   any other libraries.

5. **Recompile the APK:** Once you've made your modifications, recompile
   the APK with apktool:
   ```sh
   java -jar /path/to/apktool_2.7.0.jar b /path/to/folder -o app-changed.apk
   ```

6. **Sign the APK:** Use apksigner to sign your recompiled APK. This is
   necessary because Android requires all apps to be digitally signed
   with a certificate before they can be installed or updated.
   ```sh
   apksigner sign --verbose --ks-pass pass:android --ks debug.keystore "app.apk"
   ```

7. **Install and Run the APK:** Install the signed, recompiled APK on
   your Android device or emulator. Monitor its operation with adb
   logcat, and perform any necessary testing or analysis.

8. ????

9. Profit

## Command examples
```sh
# For decoding the dex files and making the apk file readable
$ jadx -d /path/to/output -e /path/to/app.apk

# For decompiling and recompiling an apk
$ java -jar /path/to/apktool_2.7.0.jar d app.apk -o /path/to/folder
$ java -jar /path/to/apktool_2.7.0.jar b /path/to/folder -o app-changed.apk

# Find header files quickly on mac
$ find /Library -name jni.h

# Terminal adb loggin
$ adb logcat | logcat-colorize

# Frida (-U is the default usb device)
$ frida-trace -U -i "Java_*" 8425
$ frida-ps -U # ps but for android processes

# Creating keystore
$ keytool -genkey -v -keystore custom.keystore -alias mykeyaliasname -keyalg RSA -keysize 2048 -validity 10000

# Sign recompiled apks
$ apksigner sign --verbose --ks-pass pass:android --ks debug.keystore "app.apk"
$ apksigner verify --verbose "app.apk"

$ java -jar ~/Downloads/apktool_2.7.0.jar d ./source/Old\ School\ RuneScape_213.2_Apkpure_original.apk -o ./apps/osrs-app
$ java -jar ~/Downloads/apktool_2.7.0.jar b ./apps/osrs-app -o ./target/osrs.apk

$ adb shell netstat -ln | grep 27042
```


### Resources
This project leverages several resources for understanding Android
runtime, Frida, LIEF, and QBDI. 
Android runtime
  - https://source.android.com/docs/core/runtime/art-ti
  - https://developer.android.com/guide/practices/verifying-apps-art.html

Frida
  - https://frida.re/docs/android/
  - https://codeshare.frida.re/ 
  - Frida-gadget
    - https://frida.re/docs/gadget/
    - https://koz.io/using-frida-on-android-without-root/
    - https://lief-project.github.io/doc/latest/tutorials/09_frida_lief.html#id9

LIEF
  - https://lief-project.github.io//doc/latest/


  - https://fadeevab.com/frida-gadget-injection-on-android-no-root-2-methods/

QBDI
   - https://github.com/QBDI/QBDI
