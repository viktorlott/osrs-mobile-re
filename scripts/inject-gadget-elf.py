#!/usr/bin/env python3

import lief

libnative = lief.parse("apps/osrs-app/lib/arm64-v8a/liblibs.hal.system.osclient.so")

# I'm scared of accidentally adding more dls to the binary
if 'libabc.so' in libnative.libraries:
    print("libabc is already injected")
    exit(1)

# Create a copy
libnative.write("source/liblibs.hal.system.osclient.so")

# Prepend gadget to dl list
libnative.add_library("libabc.so")

# OBS, this will overwrite the parsed binary
libnative.write("apps/osrs-app/lib/arm64-v8a/liblibs.hal.system.osclient.so")

# Make sure libabc.so is first in the list
print(libnative.libraries);