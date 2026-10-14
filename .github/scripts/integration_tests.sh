#!/usr/bin/env bash
# Runs the example app's integration tests on an Android emulator or, when
# SIMULATOR_UDID is set, on that iOS Simulator. Run from example/.
#
# On a freshly booted emulator or Simulator, `flutter test` sometimes launches
# the app and then never reports back, and waits until the job times out.
# Each attempt is therefore limited to five minutes, and only such a hang gets
# one more attempt; a failing test fails the job right away. The device log is
# printed after every failed attempt. The tests log "integration test: <name>"
# when each one starts, so the log shows where a hang happened.
#
# Written for the bash 3.2 that macOS ships, which has no `timeout`.

android_app=dev.shewa.flutter_anti_virtuals_example
ios_app=dev.shewa.flutterAntiVirtualsExample
udid=${SIMULATOR_UDID:-}
limit=300
timed_out=124

# Runs "$@" and returns its status, or $timed_out when it ran past $limit
# seconds and had to be stopped.
run_limited() {
  local flag
  flag=$(mktemp)
  rm -f "$flag"
  "$@" &
  local pid=$!
  (
    sleep "$limit"
    touch "$flag"
    kill -TERM "$pid" 2>/dev/null
    sleep 10
    kill -KILL "$pid" 2>/dev/null
  ) &
  local watchdog=$!
  wait "$pid"
  local status=$?
  kill "$watchdog" 2>/dev/null
  wait "$watchdog" 2>/dev/null
  if [ -e "$flag" ]; then
    rm -f "$flag"
    return "$timed_out"
  fi
  return "$status"
}

run_tests() {
  if [ -n "$udid" ]; then
    flutter test integration_test -d "$udid" --dart-define=EXPECT_EMULATOR=true
  else
    flutter test integration_test --dart-define=EXPECT_EMULATOR=true
  fi
}

print_device_log() {
  if [ -n "$udid" ]; then
    xcrun simctl spawn "$udid" log show --last 6m --style compact \
      --predicate 'process == "Runner"' 2>/dev/null | tail -n 300
  else
    adb logcat -d -t 500
  fi
}

reset_app() {
  if [ -n "$udid" ]; then
    xcrun simctl terminate "$udid" "$ios_app" 2>/dev/null
  else
    adb shell am force-stop "$android_app"
    adb logcat -c
  fi
}

if [ -z "$udid" ]; then adb logcat -c; fi

for attempt in 1 2; do
  run_limited run_tests
  status=$?
  if [ "$status" -eq 0 ]; then
    exit 0
  fi
  echo "::group::device log after attempt $attempt"
  print_device_log
  echo "::endgroup::"
  if [ "$status" -ne "$timed_out" ]; then
    exit "$status"
  fi
  echo "::warning::flutter test did not finish within $limit seconds (attempt $attempt)"
  reset_app
done
exit 1
