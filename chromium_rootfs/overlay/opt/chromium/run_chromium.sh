#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Boot-time Chromium checks. Every status line printed here reflects a real
# exit code or real output; nothing is substituted on failure.
CHROMIUM_URL="${CHROMIUM_URL:-https://www.yahoo.com/}"

# Give XFCE desktop components time to initialize and map
echo "[rc.sysinit] Waiting 45s for XFCE desktop components to settle..."
sleep 45

echo "[rc.sysinit] Verifying 32-bit SwiftShader Vulkan + ANGLE OpenGL ES 3.1..."
/opt/chromium/swiftshader_probe
ss_status=$?
echo "[rc.sysinit] SWIFTSHADER_PROBE_EXIT=$ss_status"
[ "$ss_status" -eq 0 ] || exit 1

[ -x /opt/chromium/chrome ] || { echo "[rc.sysinit] /opt/chromium/chrome missing"; exit 1; }

# 1) Headless variant (headless_shell): the marker is computed by JavaScript in the page, so it
#    can only appear in the dumped DOM if Blink + V8 actually ran.
echo "[rc.sysinit] Chromium headless (headless_shell): --dump-dom file:///opt/chromium/headless_test.html"
mkdir -p /tmp/chrome-headless
rm -f /tmp/headless_dom.html /tmp/headless_err.log
# (BusyBox `timeout` relies on vfork semantics the shim emulates differently,
#  so a plain shell watchdog is used instead.)
/usr/bin/chromium-headless --user-data-dir=/tmp/chrome-headless \
  --dump-dom file:///opt/chromium/headless_test.html >/tmp/headless_dom.html 2>/tmp/headless_err.log &
hl_pid=$!
hl_waited=0
hl_timed_out=0
while kill -0 "$hl_pid" 2>/dev/null; do
  if [ "$hl_waited" -ge 180 ]; then
    hl_timed_out=1
    echo "[rc.sysinit] Headless Chromium still running after 180s; killing it"
    kill -9 "$hl_pid" 2>/dev/null
    break
  fi
  sleep 1
  hl_waited=$((hl_waited + 1))
done
wait "$hl_pid" 2>/dev/null
hl_status=$?
echo "[rc.sysinit] Headless Chromium finished after ${hl_waited}s"
if grep -q '<div id="r">NT51_JS_RESULT_42_71</div>' /tmp/headless_dom.html 2>/dev/null && grep -q '</html>' /tmp/headless_dom.html 2>/dev/null; then
  echo "[rc.sysinit] Headless DOM: NT51_JS_RESULT_42_71"
  echo "[rc.sysinit] CHROMIUM_HEADLESS_DOM_VALID=1"
else
  echo "[rc.sysinit] CHROMIUM_HEADLESS_DOM_VALID=0"
  echo "[rc.sysinit] Headless failed; stderr tail:"
  tail -n 20 /tmp/headless_err.log 2>/dev/null
fi
echo "[rc.sysinit] CHROMIUM_HEADLESS_EXIT=$hl_status"
echo "[rc.sysinit] CHROMIUM_HEADLESS_TIMED_OUT=$hl_timed_out"

# 2) Normal GUI variant on the XFCE 4.18 desktop (Xvfb :0).
echo "[rc.sysinit] Launching Chromium GUI on XFCE 4.18 (:0) -> $CHROMIUM_URL"
mkdir -p /tmp/chrome-gui
/usr/bin/chromium --user-data-dir=/tmp/chrome-gui \
  --window-position=18,28 --window-size=764,536 "$CHROMIUM_URL" &
sleep 15
echo "[rc.sysinit] Chromium GUI launched (pid $!)."
