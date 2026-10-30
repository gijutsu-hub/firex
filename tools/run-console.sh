#!/usr/bin/env bash
# Launch the FireX desktop console on this machine, straight from a build
# tree -- no image, no VM, no root.
#
# The console is a CLIENT of firexd, so there has to be a daemon for it to
# sign in against. Started by hand that is four commands and a user
# database nobody remembers creating, and the first thing you see is
# "firexd is not running". This does the whole thing and takes it down
# again on the way out.
#
# The daemon runs with --no-apply, so it parses the configuration and
# serves the API without touching this machine's interfaces, routes or
# firewall rules. That is what makes it safe to run on a workstation.
#
#   tools/run-console.sh                  windowed, admin/admin
#   tools/run-console.sh --port 9000      a different dev port
#   tools/run-console.sh --kiosk          as the appliance runs it
#   tools/run-console.sh --keep           leave the daemon running
set -euo pipefail

PROJ="$(cd "$(dirname "$0")/.." && pwd)"
PORT=18080
KEEP=0
ARGS=()

while [ $# -gt 0 ]; do
    case "$1" in
        --port) PORT="$2"; shift 2 ;;
        --keep) KEEP=1; shift ;;
        --help|-h)
            sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) ARGS+=("$1"); shift ;;
    esac
done

for b in firexd flamewall; do
    [ -x "$PROJ/$b" ] || { echo "run-console: $PROJ/$b is not built -- run: make" >&2; exit 1; }
done

STATE="$PROJ/build/dev"
mkdir -p "$STATE"
USERS="$STATE/users"

# admin/admin, the same pair the appliance ships with, so the habit
# carries over. --allow-weak because the daemon would otherwise refuse a
# password this short, which is the right default everywhere but here.
if [ ! -s "$USERS" ]; then
    printf 'admin\n' | "$PROJ/firexd" --passwd admin --role admin \
        --allow-weak --users "$USERS" >/dev/null
    echo "run-console: created a dev account -- admin / admin"
fi

DAEMON_PID=""
cleanup() {
    if [ -n "$DAEMON_PID" ] && [ "$KEEP" = 0 ]; then
        kill "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
        echo "run-console: stopped the dev daemon"
    fi
}
trap cleanup EXIT INT TERM

# Reuse whatever is already there rather than starting a second daemon on
# a port that is taken -- two of them would fight over the same state.
if (exec 3<>/dev/tcp/127.0.0.1/"$PORT") 2>/dev/null; then
    echo "run-console: something already answers on port $PORT; using it"
else
    "$PROJ/firexd" --no-apply --blockpage-port "$PORT" \
        --enterprise-config "$PROJ/config/firex.conf" \
        --rules "$PROJ/config/rules.conf" \
        --users "$USERS" > "$STATE/firexd.log" 2>&1 &
    DAEMON_PID=$!

    for _ in $(seq 1 50); do
        (exec 3<>/dev/tcp/127.0.0.1/"$PORT") 2>/dev/null && break
        kill -0 "$DAEMON_PID" 2>/dev/null || {
            echo "run-console: the daemon exited at once; last lines:" >&2
            tail -5 "$STATE/firexd.log" >&2
            exit 1
        }
        sleep 0.1
    done
    echo "run-console: dev daemon on 127.0.0.1:$PORT (log: $STATE/firexd.log)"
fi

echo "run-console: sign in as admin / admin"
cd "$PROJ"          # so the console finds board/splash/logo.png
exec_rc=0
"$PROJ/flamewall" --port "$PORT" "${ARGS[@]}" || exec_rc=$?
exit "$exec_rc"
