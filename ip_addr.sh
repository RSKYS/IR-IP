#!/bin/sh

# Copyright 2026 Reza Talebi, Shahin Shahr, Iran.
# Copyright 2026 Pouria Rezaei <Pouria.rz@outlook.com>
# All rights reserved.
#
# Redistribution and use of this script, with or without modification, is
# permitted provided that the following conditions are met:
#
# 1. Redistributions of this script must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
#  THIS SOFTWARE IS PROVIDED BY THE AUTHOR "AS IS" AND ANY EXPRESS OR IMPLIED
#  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
#  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO
#  EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
#  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
#  OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
#  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
#  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
#  ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

DEFAULT_IP_FILE="./ir.txt"

usage() {
	cat <<EOF
Usage:
  $0 add
  $0 del (delete)
  $0 help

Description:
  Reads routes from a file and adds or deletes them from the system routing table.

Actions:
  add       Add or replace routes from ir.txt
  del       Delete routes from ir.txt
  delete    Same as del
  help      Show this help message

Input file:
  Default: ./ir.txt
  Optional: pass a custom file as the second argument

Supported formats inside the input file:
  37.202.247.100
  2.144.0.0/14
  185.113.9.0/24

Notes:
  - Single IPs without a prefix are treated as /32.
  - CIDR routes like 2.144.0.0/14 are used as-is.
  - Empty lines are ignored.
  - Comments are supported with #.

Examples:
  $0 add
  $0 add file.txt
  $0 del
  $0 del file.txt
EOF
}

action=${1:-}
ip_file=${2:-"$DEFAULT_IP_FILE"}

case "$action" in
	add|del|delete)
		;;
	""|help|-h|--help)
		usage
		exit 0
		;;
	*)
		echo "Unknown action: $action" >&2
		usage >&2
		exit 1
		;;
esac

if [ "$#" -gt 2 ]; then
	echo "Too many arguments" >&2
	usage >&2
	exit 1
fi

if [ ! -f "$ip_file" ]; then
	echo "Route file not found: $ip_file" >&2
	exit 1
fi

gateway=
iface=

if [ "$action" = "add" ]; then
	default_route=$(
		ip -4 route show default 2>/dev/null | awk '/ via / { print; exit }' || true
	)

	if [ -z "$default_route" ]; then
		echo "No default route found" >&2
		exit 1
	fi

	gateway=$(printf '%s\n' "$default_route" | awk '
		{
			for (i = 1; i <= NF; i++) {
				if ($i == "via") {
					print $(i + 1)
					exit
				}
			}
		}
	')

	iface=$(printf '%s\n' "$default_route" | awk '
		{
			for (i = 1; i <= NF; i++) {
				if ($i == "dev") {
					print $(i + 1)
					exit
				}
			}
		}
	')

	if [ -z "$gateway" ] || [ -z "$iface" ]; then
		echo "Could not parse gateway or interface" >&2
		echo "Default route was: $default_route" >&2
		exit 1
	fi

	echo "Using gateway: $gateway"
	echo "Using interface: $iface"
fi

echo "Reading routes from: $ip_file"

while IFS= read -r line || [ -n "$line" ]; do
	line=$(printf '%s\n' "$line" \
		| sed 's/\r$//' \
		| sed 's/[[:space:]]*#.*$//' \
		| sed 's/^[[:space:]]*//' \
		| sed 's/[[:space:]]*$//')

	[ -z "$line" ] && continue

	case "$line" in
		*/*)
			route=$line
			;;
		*)
			route="$line/32"
			;;
	esac

	case "$action" in
		add)
			echo "Adding route for $route"
			ip route replace "$route" via "$gateway" dev "$iface"
			;;
		del|delete)
			echo "Deleting route for $route"
			ip route del "$route" 2>/dev/null || echo "Not found: $route"
			;;
	esac
done < "$ip_file"

echo "Done."
