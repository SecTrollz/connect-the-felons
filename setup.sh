#!/data/data/com.termux/files/usr/bin/bash
# ══════════════════════════════════════════════════════════════════
# Connect the Felons - Build Setup
# ══════════════════════════════════════════════════════════════════
# The Android SDK command-line tools (sdkmanager, Gradle daemon) all
# crash on Termux with a PerfettoTrace JNI abort because they expect
# Android-internal classes that don't exist in Termux's OpenJDK.
# This is a known hard incompatibility, not a config problem.
#
# The working path is GitHub Actions: push your code, a free Ubuntu
# CI runner builds the APK, you download it. Takes ~5 minutes total.
#
#   bash push_to_github.sh
#
# See README.md for the full build paths.
# ══════════════════════════════════════════════════════════════════

echo ""
echo "═══ Connect the Felons - Build ═══"
echo ""
echo "The Android SDK tools (sdkmanager, Gradle daemon) crash on"
echo "Termux with a JNI abort (PerfettoTrace) - this is a known"
echo "hard incompatibility with Termux's OpenJDK, not a config"
echo "problem. It cannot be fixed by changing env vars."
echo ""
echo "The working path:"
echo ""
echo "  bash push_to_github.sh"
echo ""
echo "This creates a private GitHub repo, pushes your code, and"
echo "GitHub Actions builds the APK on a free Ubuntu runner."
echo "You download the APK from the Actions tab. ~5 minutes."
echo ""
echo "You need a free GitHub account and a Personal Access Token."
echo "Details in README.md."
echo ""
