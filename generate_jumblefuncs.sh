#!/usr/bin/env bash
#
# generate_jumblefuncs.sh
#
# Regenerate the pgNN_jumblefuncs.{switch,funcs}.c files that jumblefuncs.c
# #includes, from a PostgreSQL source tree.
#
# These files are the queryjumblefuncs.{switch,funcs}.c output of PostgreSQL's
# src/backend/nodes/gen_node_support.pl, renamed per major version. The source
# tree must be checked out to a branch that carries the pg_stat_plans plan-ID
# jumble changes (the "Add plan ID jumble funcs" commit: array_size/JUMBLE_ARRAY
# support in gen_node_support.pl plus the plan-node annotations in
# plannodes.h / primnodes.h).
#
# The generator runs standalone with perl -- no configure/build of PostgreSQL
# is required, it just parses the node header files.
#
# Usage:
#   ./generate_jumblefuncs.sh pg19 ~/Code/postgres
#   ./generate_jumblefuncs.sh pg18 /path/to/pg18-src
#
# The header list and its required ordering are read from the target tree's own
# gen_node_support.pl (@all_input_files), so this works across major versions.

set -euo pipefail

if [ "$#" -ne 2 ]; then
	echo "usage: $0 <label e.g. pg19> <path-to-postgres-source>" >&2
	exit 1
fi

label=$1
pgsrc=$2
here=$(cd "$(dirname "$0")" && pwd)

gen=$pgsrc/src/backend/nodes/gen_node_support.pl
incdir=$pgsrc/src/include

if [ ! -f "$gen" ]; then
	echo "error: $gen not found (is '$pgsrc' a PostgreSQL source tree?)" >&2
	exit 1
fi

# Extract @all_input_files (the node headers, in the exact order the generator
# asserts) from the target tree's gen_node_support.pl.
# (read loop instead of mapfile for bash 3.2 / macOS compatibility)
headers=()
while IFS= read -r h; do
	headers+=("$h")
done < <(perl -ne '
	$in = 1 if /\@all_input_files\s*=\s*qw\(/;
	next unless $in;
	$in = 0, last if /^\s*\)\s*;/;
	while (/([\w\/]+\.h)/g) { print "$1\n"; }
' "$gen")

if [ "${#headers[@]}" -eq 0 ]; then
	echo "error: could not parse \@all_input_files from $gen" >&2
	exit 1
fi

args=()
for h in "${headers[@]}"; do
	args+=("$incdir/$h")
done

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "Generating jumble funcs for $label from $pgsrc"
echo "  branch: $(git -C "$pgsrc" rev-parse --abbrev-ref HEAD 2>/dev/null || echo '?')"
echo "  headers: ${#headers[@]}"

(cd "$pgsrc/src/backend/nodes" && perl "$gen" --outdir "$tmp" "${args[@]}")

for kind in switch funcs; do
	src=$tmp/queryjumblefuncs.$kind.c
	dst=$here/${label}_jumblefuncs.$kind.c
	if [ ! -f "$src" ]; then
		echo "error: generator did not produce $src" >&2
		exit 1
	fi
	cp "$src" "$dst"
	echo "  wrote $(basename "$dst") ($(wc -l < "$dst") lines)"
done

echo "Done."
