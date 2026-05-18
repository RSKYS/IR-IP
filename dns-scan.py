#!/usr/bin/env python3

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

from __future__ import annotations
import argparse
import ipaddress
import subprocess
from pathlib import Path
from typing import Iterator, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

DNS_TIMEOUT_SECONDS = 2
DNS_QUERY_DOMAIN = "google.com"
PARALLEL = 88
PING_TIMEOUT_SECONDS = 2

def is_valid_ipv4(value: str) -> bool:
	try:
		ipaddress.IPv4Address(value)
		return True
	except ipaddress.AddressValueError:
		return False

def ping_reachable(ip: str) -> bool:
	try:
		result = subprocess.run(
			["ping", "-c", "1", "-W", str(PING_TIMEOUT_SECONDS), ip],
			stdout=subprocess.DEVNULL,
			stderr=subprocess.DEVNULL,
			timeout=PING_TIMEOUT_SECONDS + 2,
			check=False,
		)
		return result.returncode == 0
	except (OSError, subprocess.SubprocessError):
		return False

def dns_resolver_responds(ip: str) -> bool:
	base_args = [
		"dig",
		f"@{ip}",
		DNS_QUERY_DOMAIN,
		"+short",
		"+nocmd",
		"+noquestion",
		"+nostats",
		f"+time={DNS_TIMEOUT_SECONDS}",
		"+tries=1",
	]

	try:
		udp = subprocess.run(
			base_args,
			stdout=subprocess.PIPE,
			stderr=subprocess.DEVNULL,
			timeout=DNS_TIMEOUT_SECONDS + 2,
			check=False,
			text=True,
		)
		if udp.returncode == 0 and udp.stdout.strip():
			return True

		tcp = subprocess.run(
			base_args + ["+tcp"],
			stdout=subprocess.PIPE,
			stderr=subprocess.DEVNULL,
			timeout=DNS_TIMEOUT_SECONDS + 2,
			check=False,
			text=True,
		)
		return tcp.returncode == 0 and bool(tcp.stdout.strip())
	except (OSError, subprocess.SubprocessError):
		return False

def check_ip(ip: str, only_resolv: bool, only_ping: bool) -> Tuple[str, str]:
	if not is_valid_ipv4(ip):
		return ip, "SKIP invalid"

	if only_resolv:
		return (ip, "OK") if dns_resolver_responds(ip) else (ip, "FAIL 53")

	if only_ping:
		return (ip, "OK") if ping_reachable(ip) else (ip, "FAIL ping")

	if not ping_reachable(ip):
		return ip, "FAIL ping"
	if not dns_resolver_responds(ip):
		return ip, "FAIL 53"
	return ip, "OK"

def iter_input_ips(path: Path) -> Iterator[str]:
	with path.open("r", encoding="utf-8", errors="replace") as handle:
		for raw in handle:
			line = raw.strip()
			if not line or line.startswith("#"):
				continue
			if "#" in line:
				line = line.split("#", 1)[0].strip()
			if line:
				yield line

def prompt_for_path(message: str, must_exist: bool = False) -> Path:
	while True:
		raw = input(message).strip().strip('"').strip("'")
		if not raw:
			print("Path cannot be empty.")
			continue

		path = Path(raw)

		if must_exist and not path.is_file():
			print(f"File not found: {path}")
			continue

		return path

def parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(
		description="Check IPv4 addresses for ping and/or DNS responsiveness."
	)
	parser.add_argument(
		"input",
		nargs="?",
		type=Path,
		help="File containing one IPv4 address per line",
	)
	parser.add_argument(
		"output",
		nargs="?",
		type=Path,
		help="File to append reachable IPs to",
	)
	parser.add_argument(
		"--only-resolv",
		action="store_true",
		help="Only test whether the IP responds on DNS (port 53)",
	)
	parser.add_argument(
		"--only-ping",
		action="store_true",
		help="Only test whether the IP responds to ICMP ping",
	)
	parser.add_argument(
		"--parallel",
		type=int,
		default=PARALLEL,
		help=f"Number of IPs to check in parallel (current: {PARALLEL})",
	)

	args = parser.parse_args()

	if args.only_resolv and args.only_ping:
		parser.error("cannot use --only-resolv and --only-ping together")

	if args.parallel < 1:
		parser.error("--parallel must be at least 1")

	if args.input is None:
		args.input = prompt_for_path("Input file: ", must_exist=True)
	elif not args.input.is_file():
		parser.error(f"input file not found: {args.input}")

	if args.output is None:
		args.output = prompt_for_path("Output file: ", must_exist=False)

	return args


def main() -> int:
	args = parse_args()

	ips = list(iter_input_ips(args.input))
	print(f"Checking {len(ips)} IPs with concurrency {args.parallel}...\n")

	with ThreadPoolExecutor(max_workers=args.parallel) as executor, args.output.open(
		"a", encoding="utf-8", buffering=1
	) as out:
		future_to_ip = {
			executor.submit(check_ip, ip, args.only_resolv, args.only_ping): ip
			for ip in ips
		}

		for future in as_completed(future_to_ip):
			ip, status = future.result()

			if status == "OK":
				print(f"[OK] {ip}")
				out.write(ip + "\n")
				out.flush()
			elif status == "SKIP invalid":
				print(f"[SKIP invalid] {ip}")
			elif status == "FAIL 53":
				print(f"[FAIL 53] {ip}")
			elif status == "FAIL ping":
				print(f"[FAIL ping] {ip}")
			else:
				print(f"[{status}] {ip}")

	return 0

if __name__ == "__main__":
	raise SystemExit(main())
