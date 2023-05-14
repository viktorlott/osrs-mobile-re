#!/usr/bin/env python3

import lief

libnative = lief.parse("apps/osrs-app/lib/arm64-v8a/liblibs.hal.system.osclient.so")
libnative.add_library("libabc.so") # Injection!
libnative.write("target/lib/arm64-v8a/liblibs.hal.system.osclient2.so")