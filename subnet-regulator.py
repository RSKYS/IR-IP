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
import ipaddress
import sys
from pathlib import Path
from typing import Optional

INVALID_EXAMPLE_LIMIT = 15

def prompt_path(prompt: str) -> str:
	while True:
		value = input(prompt).strip().strip('"')
		if value:
			return value
		print("Please enter a non-empty path.")


def parse_ipv4_entry(text: str) -> Optional[ipaddress.IPv4Network]:
	stripped = text.strip()
	if not stripped or stripped.startswith("#"):
		return None

	try:
		network = ipaddress.ip_network(stripped, strict=False)
	except ValueError:
		return None

	if isinstance(network, ipaddress.IPv4Network):
		return network

	return None


def main() -> int:
	input_path = prompt_path("Enter INPUT file path: ")
	output_path = prompt_path("Enter OUTPUT file path: ")

	input_file = Path(input_path)
	output_file = Path(output_path)

	if not input_file.is_file():
		print(f"Error: input file not found: {input_file}", file=sys.stderr, flush=True)
		return 1

	try:
		output_file.parent.mkdir(parents=True, exist_ok=True)
	except OSError as exc:
		print(
			f"Error: could not create output directory '{output_file.parent}': {exc}",
			file=sys.stderr,
			flush=True,
		)
		return 1

	networks: list[ipaddress.IPv4Network] = []
	invalid_count = 0
	invalid_examples: list[tuple[int, str]] = []

	print("Reading and parsing input file...", flush=True)

	try:
		with input_file.open("r", encoding="utf-8", errors="replace") as f:
			for line_number, raw_line in enumerate(f, start=1):
				stripped = raw_line.strip()

				if not stripped or stripped.startswith("#"):
					continue

				network = parse_ipv4_entry(raw_line)
				if network is not None:
					networks.append(network)
					continue

				invalid_count += 1
				if len(invalid_examples) < INVALID_EXAMPLE_LIMIT:
					invalid_examples.append((line_number, stripped))

	except OSError as exc:
		print(f"Error reading input file: {exc}", file=sys.stderr, flush=True)
		return 1

	if not networks:
		print("No valid IPv4 entries found.", flush=True)
		try:
			output_file.write_text("", encoding="utf-8")
		except OSError as exc:
			print(f"Error writing output file: {exc}", file=sys.stderr, flush=True)
			return 1

		if invalid_count:
			print(f"Skipped {invalid_count} invalid line(s).", flush=True)
		return 0

	print(
		f"Found {len(networks):,} valid entr{'y' if len(networks) == 1 else 'ies'}.",
		flush=True,
	)
	print("Merging overlapping/adjacent ranges and removing duplicates...", flush=True)

	try:
		collapsed = list(ipaddress.collapse_addresses(networks))
	except ValueError as exc:
		print(f"Error while merging networks: {exc}", file=sys.stderr, flush=True)
		return 1

	print(f"Writing {len(collapsed):,} merged CIDR block(s) to output...", flush=True)

	try:
		with output_file.open("w", encoding="utf-8", newline="\n") as f:
			for net in collapsed:
				f.write(f"{net.with_prefixlen}\n")
	except OSError as exc:
		print(f"Error writing output file: {exc}", file=sys.stderr, flush=True)
		return 1

	print(f"\nDone! Output written to: {output_file}", flush=True)
	print(f"   Input  → {len(networks):,} valid entr{'y' if len(networks) == 1 else 'ies'}")
	print(f"   Output → {len(collapsed):,} CIDR block{'s' if len(collapsed) != 1 else ''}")

	if invalid_count:
		print(f"\nSkipped {invalid_count} invalid line(s).", flush=True)
		if invalid_examples:
			print("First few invalid lines:", flush=True)
			for line_number, text in invalid_examples:
				print(f"  Line {line_number}: {text!r}", flush=True)

	return 0


if __name__ == "__main__":
	try:
		raise SystemExit(main())
	except KeyboardInterrupt:
		print("\nCancelled by user.", file=sys.stderr, flush=True)
		raise SystemExit(130) from None
	