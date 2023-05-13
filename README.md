# OSRS Native Android mobile app
### UNDER DEVELOPMENT

## Goal
- Learn about RE techniques.
- Document everything.
- Build a working wrapping for tracking internal game state. 

### Terminologies
- ARM ISA
- Linux kernel
- Android OS
- Android NDT, JNI and AGDK
- Dalvik VM and ART (Android runtime) 
- Android Java bytecode (smali)
- Dalvik Executable (.dex files)
- ELF and Shared object (.so)

### Tools
| Name           | Description                                          | Required |
|:---------------|:-----------------------------------------------------|:--------:|
| Java 8/11      | JDK                                                  |          |
| Android studio | IDE for android apps                                 |          |
| apksigner      | Used to sign the recompiled apk                      |    X     |
| emulator       | The Android emulator that will run the modified apk  |    X     |
| adb            | Interact with the emulator                           |          |
| Ghidra         | Used to decode the binary (Reverse engineering tool) |          |
| frida-tools    | RE tool for runtime analysis                         |    X     |
| apktool        | Used for de/re-compilation                           |    X     |
| jadx           | Used to convert a apk to readable java code          |          |
| dextools       | Dalvik executable tools                              |          |
| Hex editor     | Used to edit the binary (I use Hex Fiend on mac)     |          |


### Disassembling and Decompiling
This section will be about RE techniques and good practices. 
- Include header files from NDK, AGDK and Android.
  - *android-ndk-r25c/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/include*
  - *android-ndk-r25c/prebuilt/linux-x86_64/include*
  - *android-ndk-r25c/sources*
  - *Java/JavaVirtualMachines/jdk-20.jdk/Contents/Home/include*

### Did you know..
- **Dalvik/ART** VM uses a register-based architecture (register machine), 
  while JVM uses stack-based architecture (stack machines).

- **ART** (Anroid Runtime) replaced Dalvik VM in Android Lollipop version.
  - ART uses AOT (Ahead-of-time) compilation
  - DVM uses JIT (Just-in-time) compilation.

- Android apps are first compiled into Java bytecode, then into Dalvik bytcode.

- The smali format is a human-readable Dex bytecode.

- **JNI** (Java Native Interface) bindings are used by the Dalvik/ART VM to
  call native functions in binaries, and vise versa. 

- **NDK** (Native Development Kit) is a toolkit that allows developers to write native
  code to interface with Dalvik/ART VM through JNI.

- **AGDK** (Android Game Development Kit) is a toolkit which contains
  libraries that assists the developer in writing Android games in
  native code. It can also interface with the Dalvik/ART VM because it
  also uses NDK and JNI. Note that it does not always need to use them
  because AGDK contains libraries that can interact independent of JNI.


### Formats
- .a files  - Archive libraries are statically linked
- .so files - Shared objects are dynamically linked

## Things I've discovered.
The OSRS Android app is developed either as an Android Native c++, Game
Activity c++ project, or a port from the RS3 NXT engine, meaning that
they might have ported the game engine and then added a android native
wrapper on top of it. 

> The JNI bindings are used in both projects, but it's never automatically
> added to Game Activity c++ projects (except for the AGDK parts). What I
> mean is that there's no `stringFromJNI` native method example present in
> GA, like there is in the Android Native c++ project. 

#### The story so far
By analysing the .so with **Ghidra**, and attaching the jni.h file to the
data type manager, I've discover a lot more things about the actual
binary. For example, it uses the NDK to natively attach it self to the
touch event listener and then concurrenly polls events from the event
queue, without involving the top java wrapper. I'm pretty new at this, 
but that took me a while to understand. If one inspect the Android Manifest,
one could see under `<Application>` `<activity android:configChanges=".." >` 
that it uses `touchscreen` such that changes to the touchscreen can be
handled (or intercepted) by the binary (OBS, this is not the same as
regular touch events).

One thing that I still want to explore is the Android NativeActivity class bindings.
If I were to inject or override the class, I could potentially intercept all actions
being made. This could either be done under compile-time, or during runtime with tools
like **frida**. 

Network... (TODO)

Shaders... (TODO)

> The GL shader definitions are for sure present in the binary.

## Steps
1. Download the OSRS apk somewhere (I'm not allowed to link it here)
2. 

  

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

# Frida
$ frida-trace -U -i "Java_*" 8425
$ frida-ps -U
```


### Structure
- source/app.apk        - The apk that will be edited 
- apps/*                - The decompiled apk
- target/app-edited.apk - The recompiled apk




# Resources
Android runtime
  - https://source.android.com/docs/core/runtime/art-ti
  - https://developer.android.com/guide/practices/verifying-apps-art.html

