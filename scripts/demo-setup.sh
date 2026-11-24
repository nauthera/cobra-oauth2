#!/usr/bin/env bash
# Prepares a shell for recording demo.gif; demo.tape sources it while hidden.
#
# It builds examples/nauthera as "nauthera", starts internal/cmd/demoidp (a
# local fake server configured like nauthera-server) and exports what the
# example reads. Source it from the repository root:
#
#   source scripts/demo-setup.sh
#
# demo_teardown stops the server and removes the build directory.

demo_dir=$(mktemp -d)
go build -o "$demo_dir/nauthera" ./examples/nauthera || return 1
go build -o "$demo_dir/demoidp" ./internal/cmd/demoidp || return 1

"$demo_dir/demoidp" >"$demo_dir/env" &
demo_pid=$!
for _ in $(seq 50); do
	[ -s "$demo_dir/env" ] && break
	sleep 0.1
done
if [ ! -s "$demo_dir/env" ]; then
	echo "demo-setup: the demo server did not start" >&2
	return 1
fi
# shellcheck disable=SC1091
. "$demo_dir/env"
export PATH="$demo_dir:$PATH"

demo_teardown() {
	kill "$demo_pid" 2>/dev/null
	rm -rf "$demo_dir"
}
