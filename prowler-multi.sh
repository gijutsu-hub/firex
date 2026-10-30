#!/usr/bin/env bash
# prowler-multi.sh - run Prowler AWS scans across several named AWS profiles.
#
# Prowler's --profile takes exactly one profile per invocation, so this loops.
# Each profile gets its own output directory and log file.
#
# Usage:
#   ./prowler-multi.sh [options] [profile ...]
#
# Options:
#   -j N        run up to N scans concurrently (default: 1)
#   -o DIR      output root directory (default: ./prowler-output)
#   -f REGION   limit scan to REGION; repeatable. Default: all enabled regions
#   -F FMT      output formats, comma separated (default: csv,html,json-ocsf)
#   -n          dry run: print the commands without running them
#   -h          show this help
#
# With no profile arguments, every profile found in ~/.aws is scanned.

set -uo pipefail

JOBS=1
OUT_ROOT="./prowler-output"
REGIONS=()
FORMATS="csv,html,json-ocsf"
DRY_RUN=0

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

usage() { awk 'NR>1 && /^#/ {sub(/^# ?/, ""); print; next} NR>1 {exit}' "$0"; exit 0; }

while getopts ':j:o:f:F:nh' opt; do
  case "$opt" in
    j) JOBS="$OPTARG" ;;
    o) OUT_ROOT="$OPTARG" ;;
    f) REGIONS+=("$OPTARG") ;;
    F) FORMATS="$OPTARG" ;;
    n) DRY_RUN=1 ;;
    h) usage ;;
    :) die "option -$OPTARG needs a value" ;;
    \?) die "unknown option -$OPTARG (try -h)" ;;
  esac
done
shift $((OPTIND - 1))

[[ "$JOBS" =~ ^[1-9][0-9]*$ ]] || die "-j needs a positive integer, got '$JOBS'"
command -v prowler >/dev/null 2>&1 || die "prowler not on PATH"

# ---- work out which profiles to scan -----------------------------------
discover_profiles() {
  { [[ -r "$HOME/.aws/credentials" ]] && sed -n 's/^[[:space:]]*\[\([^]]*\)\].*/\1/p' "$HOME/.aws/credentials"
    [[ -r "$HOME/.aws/config" ]] && sed -n 's/^[[:space:]]*\[profile \([^]]*\)\].*/\1/p' "$HOME/.aws/config"
  } | sed 's/[[:space:]]*$//' | grep -v '^default$' | sort -u
}

if (($# > 0)); then
  PROFILES=("$@")
else
  mapfile -t PROFILES < <(discover_profiles)
  ((${#PROFILES[@]})) || die "no profiles found in ~/.aws - name them as arguments instead"
  printf 'Discovered %d profile(s): %s\n' "${#PROFILES[@]}" "${PROFILES[*]}"
fi

# ---- preflight: confirm each profile's credentials actually work -------
PROWLER_PY="$(dirname "$(readlink -f "$(command -v prowler)")")/python"

preflight() {
  local profile="$1"
  [[ -x "$PROWLER_PY" ]] || return 0   # can't check, let prowler decide
  "$PROWLER_PY" -I -c "
import sys, boto3
try:
    ident = boto3.Session(profile_name=sys.argv[1]).client('sts').get_caller_identity()
    print(ident['Account'])
except Exception as e:
    print('%s: %s' % (type(e).__name__, e), file=sys.stderr)
    sys.exit(1)
" "$profile" 2>&1
}

# ---- run one profile ---------------------------------------------------
run_one() {
  local profile="$1"
  local dir="$OUT_ROOT/$profile"
  local log="$dir/prowler.log"
  local -a cmd=(prowler aws --profile "$profile"
                --output-directory "$dir"
                --output-formats ${FORMATS//,/ }
                --log-file "$log"
                --no-banner --ignore-exit-code-3)
  ((${#REGIONS[@]})) && cmd+=(--region "${REGIONS[@]}")

  if ((DRY_RUN)); then
    printf '[%s] would run: %s\n' "$profile" "${cmd[*]}"
    return 0
  fi

  mkdir -p "$dir"

  local acct
  if ! acct="$(preflight "$profile")"; then
    printf '[%s] SKIPPED - credentials rejected: %s\n' "$profile" "$acct" >&2
    return 2
  fi
  printf '[%s] starting (account %s)\n' "$profile" "$acct"

  local start=$SECONDS
  if "${cmd[@]}" >"$dir/stdout.txt" 2>&1; then
    printf '[%s] done in %ds -> %s\n' "$profile" "$((SECONDS - start))" "$dir"
    return 0
  else
    local rc=$?
    printf '[%s] FAILED (exit %d) - see %s\n' "$profile" "$rc" "$dir/stdout.txt" >&2
    return 1
  fi
}

# ---- drive the loop ----------------------------------------------------
mkdir -p "$OUT_ROOT"
declare -A STATUS=()
declare -A PID_OF=()

for profile in "${PROFILES[@]}"; do
  while (($(jobs -rp | wc -l) >= JOBS)); do wait -n 2>/dev/null || true; done
  run_one "$profile" &
  PID_OF[$profile]=$!
done

for profile in "${PROFILES[@]}"; do
  if wait "${PID_OF[$profile]}"; then STATUS[$profile]=ok
  else
    case $? in
      2) STATUS[$profile]=skipped ;;
      *) STATUS[$profile]=failed ;;
    esac
  fi
done

# ---- summary -----------------------------------------------------------
echo
echo "================ summary ================"
rc=0
for profile in "${PROFILES[@]}"; do
  printf '  %-28s %s\n' "$profile" "${STATUS[$profile]}"
  [[ "${STATUS[$profile]}" == ok ]] || rc=1
done
echo "reports under: $OUT_ROOT"
exit $rc
