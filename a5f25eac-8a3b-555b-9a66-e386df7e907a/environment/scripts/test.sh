#!/bin/bash -eu
# The project's own behaviour suite for the affected extension.
#
#   test.sh [staged_dir]
#
# Every statement here is well formed and cheap: none of them reaches the
# defect. The point is the OPPOSITE of a reproduction run. A change that
# removes the fault by disabling, capping or short-circuiting the extension
# still has to return these exact results.
set -euo pipefail

STAGED="${1:-/out/patched}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cat > "$WORK/regression.sql" <<'SQL'
SELECT json_set('{"a":1}','$.b',2);
SELECT json_replace('{"a":1}','$.a',9);
SELECT json_insert('{"a":1}','$.b',99);
SELECT json_extract('{"a":1,"b":[2,3]}','$.b[1]');
SELECT json_remove('{"a":1,"b":2}','$.a');
SELECT json_type('{"a":[1,2]}','$.a');
SELECT json_array_length('[1,2,3,4]');
SELECT json_valid('{"x":1}'), json_valid('{oops');
SELECT json_quote(3.5), json_object('k','v');
SELECT json_patch('{"a":1,"b":2}','{"b":null,"c":3}');
SELECT json_set('{}','$.a',json('1'),'$.b',json('2'),'$.c',json('3'));
SELECT json_group_array(value) FROM json_each('[1,2,3]');
SQL

cat > "$WORK/expected.txt" <<'EXPECTED'
{"a":1,"b":2}
{"a":9}
{"a":1,"b":99}
3
{"b":2}
array
4
1|0
3.5|{"k":"v"}
{"a":1,"c":3}
{"a":1,"b":2,"c":3}
[1,2,3]
EXPECTED

export ASAN_OPTIONS=detect_leaks=0
cd "$STAGED"
./sqlite3 :memory: < "$WORK/regression.sql" > "$WORK/actual.txt" 2>&1

diff -u "$WORK/expected.txt" "$WORK/actual.txt"
echo "regression suite: 12 statements, all results unchanged"
