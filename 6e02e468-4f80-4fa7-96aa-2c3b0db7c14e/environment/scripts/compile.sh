#!/bin/bash -eu
# Stage a sanitizer build of the library.
#
#   compile.sh <variant> [source_dir] [staged_dir]
#
# Two binaries land in the staged directory:
#   ossfuzz   the entry point that reads one statement file (ASan + libFuzzer)
#   sqlite3   the command line shell (ASan), used by the regression suite
#
# The single-file source is regenerated from scratch every time. Leaving a
# stale one in place makes `make` report "up to date" and relink the OLD
# sources, so a patched tree would produce an unpatched binary.
set -euo pipefail

VARIANT="${1:-patched}"
SRC_DIR="${2:-/src/sqlite3}"
OUT_DIR="${3:-/out/${VARIANT}}"

SAN="-fsanitize=address,fuzzer -fno-omit-frame-pointer -g -O1"
DEFS="-DSQLITE_MAX_LENGTH=128000000 -DSQLITE_MAX_SQL_LENGTH=128000000 \
-DSQLITE_MAX_MEMORY=25000000 -DSQLITE_PRINTF_PRECISION_LIMIT=1048576 \
-DSQLITE_DEBUG=1 -DSQLITE_MAX_PAGE_COUNT=16384"

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"
cd "$SRC_DIR"

# The image ships a toolchain whose own flags carry a fuzzing engine; the
# build below sets every flag it needs, so start from a clean environment.
export CC=clang CXX=clang++
export CFLAGS="" CXXFLAGS="" LDFLAGS="" LIB_FUZZING_ENGINE=""

[ -f Makefile ] || ./configure --disable-tcl > "$OUT_DIR/configure.log" 2>&1
rm -f sqlite3.c shell.c
make sqlite3.c shell.c > "$OUT_DIR/amalgamation.log" 2>&1

clang $SAN $DEFS -I. -c sqlite3.c      -o "$OUT_DIR/sqlite3.o"
clang $SAN $DEFS -I. -c test/ossfuzz.c -o "$OUT_DIR/ossfuzz.o"
clang $SAN "$OUT_DIR/ossfuzz.o" "$OUT_DIR/sqlite3.o" \
      -o "$OUT_DIR/ossfuzz" -lm -lpthread -ldl

clang -fsanitize=address -fno-omit-frame-pointer -g -O1 $DEFS -I. \
      shell.c sqlite3.c -o "$OUT_DIR/sqlite3" -lm -lpthread -ldl

test -x "$OUT_DIR/ossfuzz"
test -x "$OUT_DIR/sqlite3"
echo "staged $VARIANT -> $OUT_DIR"
