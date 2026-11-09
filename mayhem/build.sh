#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es). EDIT per repo.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

OUT="$SRC/mayhem/out"
FUZZ_DIR="$SRC/mayhem/build-fuzz"
TEST_DIR="$SRC/mayhem/build-test"
mkdir -p "$OUT"

# The one fuzz target is mayhem/dvbsub_enc_fuzzer.c (no upstream harness reaches the subtitle encoders),
# linked against the sanitized static libavcodec/libswresample/libavutil.
T=target_dvbsub_enc_fuzzer
TARGETS="$T"

# Features are pinned (no autodetected system libraries) so the sanitized and the oracle build are
# deterministic and need nothing from the network. No assembly: sanitizers cannot see through it.
COMMON_CONFIG="--disable-autodetect --enable-zlib --disable-doc --disable-asm --disable-x86asm --disable-ffplay"

# 1) The functional-oracle build: project's NORMAL flags (no sanitizer, no -gdwarf-3), out of tree.
#    Builds the programs plus every FATE test program, so mayhem/test.sh only RUNS them.
mkdir -p "$TEST_DIR"
(
  cd "$TEST_DIR"
  env -u CFLAGS -u LDFLAGS -u CPPFLAGS "$SRC/configure" --cc="$CC" $COMMON_CONFIG
  make -j"$MAYHEM_JOBS"
  # Everything FATE would otherwise compile on demand: host utilities and the libav* API test programs
  # that this configuration enables (a program with no make rule here belongs to a disabled component).
  progs="tests/base64 tests/tiny_psnr tests/tiny_ssim tests/audiomatch tests/audiogen tests/videogen"
  for s in "$SRC"/tests/api/api-*-test.c; do
    p="tests/api/$(basename "$s" .c)"
    if make -n "$p" >/dev/null 2>&1; then progs="$progs $p"; fi
  done
  make -j"$MAYHEM_JOBS" testprogs alltools $progs
)

# 2) lsan_off hook (leaks are not the bug class this fleet fuzzes for) + the run-once standalone driver.
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$OUT/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OUT/standalone_main.o"

# 3) The sanitized fuzz build: the WHOLE library gets $SANITIZER_FLAGS, DWARF 3 and SanCov
#    (-fsanitize=fuzzer-no-link) so the fuzzed code, not just the harness, is instrumented.
mkdir -p "$FUZZ_DIR"
(
  cd "$FUZZ_DIR"
  FUZZ_CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link"
  env -u CFLAGS -u LDFLAGS -u CPPFLAGS "$SRC/configure" --cc="$CC" $COMMON_CONFIG --disable-debug \
      --extra-cflags="$FUZZ_CFLAGS" --extra-ldflags="$SANITIZER_FLAGS"
  make -j"$MAYHEM_JOBS" libavcodec/libavcodec.a libswresample/libswresample.a libavutil/libavutil.a
  LIBS="libavcodec/libavcodec.a libswresample/libswresample.a libavutil/libavutil.a -lm -lz -latomic -pthread"
  $CC $FUZZ_CFLAGS -I"$SRC" -I"$FUZZ_DIR" -c "$SRC/mayhem/dvbsub_enc_fuzzer.c" -o "$FUZZ_DIR/dvbsub_enc_fuzzer.o"

  # 4) The libFuzzer binary, and the standalone reproducer (the run-once driver instead of libFuzzer).
  $CC $FUZZ_CFLAGS $LIB_FUZZING_ENGINE dvbsub_enc_fuzzer.o "$OUT/lsan_off.o" $LIBS -o "$OUT/$T"
  $CC $FUZZ_CFLAGS dvbsub_enc_fuzzer.o "$OUT/standalone_main.o" "$OUT/lsan_off.o" $LIBS -o "$OUT/$T-standalone"
)
