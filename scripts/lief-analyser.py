import lief

libnative = lief.parse("apps/osrs-app/lib/arm64-v8a/liblibs.hal.system.osclient.so")

print("\nHeader:")
print(libnative.header)

print("\nExported functions:")
for item in libnative.exported_functions: 
    print("- " + format(item))

print("\nLibraries:")
for item in libnative.libraries: 
    print("- " + item)


print("\nConstructor functions:")
for item in libnative.ctor_functions: 
    print("- " + format(item))


print("\nEntry point:")
print(libnative.entrypoint)


with open('nativelib.txt', 'w') as f:
    f.write(format(libnative))

