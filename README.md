# Connect the Felons (CTF)
### OSINT Forensic Investigation Platform — Android App

---

## What this is

A self-contained Android app wrapping all 9 CTF investigation modules
(M0–M8) plus the evidence journal and report engine into a home-screen
app. Type a domain, email, IP, IMEI, ICCID, phone number, or company
name — tap RUN — get a SHA-256 evidence-chained forensic report.

**No rewrite of the Python code happened here.** The same modules that
passed self-tests in the build environment are copied unchanged into
`app/src/main/python/`. The Android app is a thin Kotlin UI that calls
`Investigation().run(target)` via Chaquopy and displays what comes back.

---

## Build (Termux on-device — Pixel 9a)

```bash
# 1. One-time setup: installs Android SDK and builds the APK
bash setup.sh

# That's it. APK lands at:
#   app/build/outputs/apk/debug/app-debug.apk
#
# To install directly:
#   adb install app/build/outputs/apk/debug/app-debug.apk
```

**First build takes 10–20 minutes.** Gradle 8.6 downloads itself
(~130MB), then Chaquopy downloads the Python runtime and compiles
your five pip packages for arm64-v8a. Subsequent builds are fast.

### If setup.sh fails on aapt2

The ARM64 issue you already solved for MDMCheck. setup.sh auto-detects
arm64 and injects the override. If it still fails:

```bash
# Check what aapt2 Termux has
pkg install aapt2
which aapt2

# Manually set it in gradle.properties:
echo "android.aapt2FromMavenOverride=$(which aapt2)" >> gradle.properties
./gradlew assembleDebug
```

---

## Build (Android Studio — PC/Mac, faster)

1. Open this folder as a project in Android Studio
2. Let Gradle sync (downloads everything automatically)
3. Build → Generate Signed Bundle/APK → APK → debug
4. ADB install or sideload to Pixel 9a

---

## Project structure

```
ctf-android/
├── setup.sh                          ← run this first (Termux)
├── gradlew                           ← use this, NOT system gradle
├── gradle/wrapper/
│   ├── gradle-wrapper.jar            ← included, no system gradle needed
│   └── gradle-wrapper.properties     ← Gradle 8.6
├── app/
│   ├── build.gradle                  ← AGP 8.3.2 + Chaquopy 17.0.0
│   └── src/main/
│       ├── AndroidManifest.xml
│       ├── java/com/ctf/app/
│       │   └── MainActivity.kt       ← thin bridge to Python
│       ├── python/
│       │   ├── ctf_bridge.py         ← Chaquopy entry point
│       │   ├── main.py               ← Investigation orchestrator
│       │   ├── evidence_journal.py   ← SHA-256 chain
│       │   ├── report_engine.py      ← 5 report/letter types
│       │   └── modules/
│       │       ├── m0_input_router.py
│       │       ├── m1_infrastructure.py
│       │       ├── m2_dns_email.py
│       │       ├── m3_ownership.py
│       │       ├── m4_reverse_infra.py
│       │       ├── m5_device.py
│       │       ├── m6_graph.py
│       │       ├── m7_reconciliation.py
│       │       └── m8_attribution.py
│       └── res/
│           ├── layout/activity_main.xml
│           ├── values/{strings,themes}.xml
│           └── mipmap-*/ic_launcher.png   ← custom icon
```

---

## Versions

| Component         | Version  |
|-------------------|----------|
| Android Gradle Plugin | 8.3.2 |
| Gradle            | 8.6      |
| Chaquopy          | 17.0.0   |
| Kotlin            | 1.9.24   |
| compileSdk / targetSdk | 35  |
| minSdk            | 24       |
| JDK (Termux)      | 21       |

---

## Known risks

**sys.path / Chaquopy extraction**: `ctf_bridge.py` sets up `sys.path`
from `__file__` before any module imports. This is the most likely
failure point on first run. If you get `ImportError: No module named
'evidence_journal'`, add a log of `os.listdir(os.path.dirname(__file__))`
to ctf_bridge.py to confirm where Chaquopy extracted the files, then
adjust the path logic accordingly.

**EvidenceJournal write path**: defaults to `cwd + /investigations/`.
Under Android this becomes the app's sandboxed private dir, which is
writable — but if journal writes fail, pass `base_dir=context.filesDir`
explicitly from Kotlin (requires a small ctf_bridge.py update).
