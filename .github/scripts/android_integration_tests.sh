#!/usr/bin/env bash
# Runs the example app's integration tests on the emulator that
# android-emulator-runner started. Run from example/.
#
# On a freshly booted emulator, `flutter test` sometimes installs the app and
# then never connects to it, and waits until the job times out. Each attempt
# is therefore limited to five minutes, and only such a hang (exit code 124)
# gets one more attempt; a failing test fails the job right away. Logcat is
# printed after every failed attempt to show what the app was doing.
set -u

app=dev.shewa.flutter_anti_virtuals_example
adb logcat -c || true

for attempt in 1 2; do
  timeout 300 flutter test integration_test --dart-define=EXPECT_EMULATOR=true
  status=$?
  if [ "$status" -eq 0 ]; then
    exit 0
  fi
  echo "::group::logcat after attempt $attempt"
  adb logcat -d -t 500 || true
  echo "::endgroup::"
  if [ "$status" -ne 124 ]; then
    exit "$status"
  fi
  echo "::warning::flutter test did not finish within 5 minutes (attempt $attempt)"
  adb shell am force-stop "$app" || true
  adb logcat -c || true
done
exit 1
