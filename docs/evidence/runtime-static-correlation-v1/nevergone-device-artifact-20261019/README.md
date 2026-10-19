# Installed Nevergone binary identity

REA pulled the installed `com.hippiegame.nevergone` 1.0.9 (version code 9)
package from the connected Android device. The APK SHA-256 is
`97296efc9d32fdd46bdf2dba475aeb13adb4cc6d2957ddf02da7a5d9c56e9508`;
extracting
`lib/armeabi-v7a/libcocos2dcpp.so` gives the exact SHA-256 pinned by the
Nevergone SemanticProgramGraph/3 manifest:
`94b1ef6a9469e261183ac08199c5b0eb65c0c40b81918ca097bd32920828eb5e`.

This verifies that the graph's static binary identity matches the installed
game library. It does not provide runtime PC events: the Frida host binding was
unavailable during this inspection, so the neighboring runtime correlation
replay remains synthetic.

The structured identity record includes the REA pull evidence ID and artifact
hashes. The APK itself is not checked into the repository.
