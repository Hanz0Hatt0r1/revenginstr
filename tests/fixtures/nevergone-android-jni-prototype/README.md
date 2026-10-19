# Nevergone Android JNI prototype replay

This replay uses the installed Nevergone 1.0.9 base APK and its ARMv7
`libcocos2dcpp.so`. The APK itself is not included. The APK hash is
`97296efc9d32fdd46bdf2dba475aeb13adb4cc6d2957ddf02da7a5d9c56e9508`; its
`classes.dex` hash is
`cc10f0f1212efe65c224778c052164ee5cb18ac82764c9971e1d4080c643210d`; the
native library hash is
`94b1ef6a9469e261183ac08199c5b0eb65c0c40b81918ca097bd32920828eb5e`.

Ghidra 12.1.2 DEV with Java 21.0.12.1 imported the stripped ELF as
`nevergone-libcocos2dcpp.so` and analyzed it as `ARM:LE:32:v8`. Its program
index has 29,552 functions. The DEX contains 27 native declarations; 21 join
to one exact exported `Java_...` symbol and to the selected decompiler plan.
The remaining six declarations have no matching exported JNI symbol and are
outside this evidence format's name-based join.

The DEX declarations are independent source evidence for those 21 JNI C
interfaces: JNI requires the native entry to receive `JNIEnv *`, then `jclass`
for static methods or `jobject` for instance methods, followed by parameters
and return type from the DEX descriptor. `android-jni-prototypes.jsonl` pins
the DEX method id, APK identity, exact native-library hash, and matching
Ghidra function-index row. It does not contain game code or assets.

The baseline High-P-code inference got parameter count right for 11/21
functions (52.4%), emitted no fully known parameter lists, and knew 19/21
return shapes; all 19 known returns matched gold. No baseline candidate met
the 0.95 acceptance threshold. With the exact DEX evidence, all 21 signatures
matched the source-backed gold and were covered at that threshold. This replay
validates the exact-source evidence path; it is not a confidence-calibration
set, and it does not measure inference on the six unmapped declarations or
internal game functions.

The checked-in function index, selected decompiler snapshot, JNI evidence,
gold, baseline and improved hypotheses, and evaluator reports are outputs of
the pinned inputs. Recreate them with the exact APK and Ghidra version above:

```sh
unzip -p base.apk lib/armeabi-v7a/libcocos2dcpp.so > /tmp/nevergone-libcocos2dcpp.so
GHIDRA_HOME=/opt/ghidra /opt/ghidra/support/analyzeHeadless \
  /tmp/nevergone-ghidra Nevergone -import /tmp/nevergone-libcocos2dcpp.so \
  -analysisTimeoutPerFile 900 -max-cpu 6
GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_program_index.sh \
  /tmp/nevergone-ghidra Nevergone nevergone-libcocos2dcpp.so /tmp/program-index
GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_decompiler_parameters.sh \
  /tmp/nevergone-ghidra Nevergone nevergone-libcocos2dcpp.so decompiler-plan.tsv \
  /tmp/decompiler-parameters.jsonl
revenginstr-android-jni-prototypes base.apk /tmp/program-index.functions.tsv.gz \
  /tmp/decompiler-parameters.jsonl --output /tmp/android-jni.jsonl
revenginstr-prototype-infer /tmp/decompiler-parameters.jsonl \
  direct-call-observations.jsonl --android-jni-evidence /tmp/android-jni.jsonl \
  --output /tmp/hypotheses.jsonl
revenginstr-function-prototype-evaluate /tmp/hypotheses.jsonl gold.jsonl \
  --format-version 2 --minimum-confidence 0.95 --output /tmp/evaluation.json
```

The confidence of these source-backed candidates is exact-evidence confidence,
not a probability calibrated from this small replay.
