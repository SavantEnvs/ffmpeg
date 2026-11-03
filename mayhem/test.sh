#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"
cd "$SRC/mayhem/build-test"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# RUN FATE (FFmpeg's own regression suite) on the programs build.sh compiled. Without SAMPLES only the
# tests that need no downloaded media run: they generate their input with FFmpeg's own test sources,
# push it through the codecs/muxers/filters and diff md5/framecrc/CRC output against the reference files
# committed under tests/ref/fate. A neutered ffmpeg/ffprobe therefore fails them.
[ -x ffmpeg ] && [ -x ffprobe ] && [ -x tests/base64 ] || { echo "FATE programs missing: mayhem/build.sh must run first" >&2; emit_ctrf cmake-fate 0 1; exit 1; }
unset SAMPLES
log="$(mktemp)"
make -k -j"$MAYHEM_JOBS" fate > "$log" 2>&1
total=$(grep -c '^TEST' "$log")
failed=$(grep -cE '^make.*\*\*\* \[.*fate-.*\] Error' "$log")
if [ "$total" -lt 1000 ]; then
  echo "only $total FATE tests ran (expected thousands):" >&2; tail -20 "$log" >&2
  failed=$(( failed > 0 ? failed : 1 ))
fi
if [ "$failed" -gt 0 ]; then grep -vE '^(TEST|CC|HOSTCC|GEN|LD|AR|HOSTLD)' "$log" | tail -60 >&2; fi
rm -f "$log"
emit_ctrf "ffmpeg-fate" "$(( total > failed ? total - failed : 0 ))" "$failed" 0
