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

import argparse
import asyncio
import random
import socket
import ssl
import struct
import sys
from collections import OrderedDict
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

DNS_SERVERS = ["1.1.1.1", "4.2.2.4"]
MAX_PARALLEL = 25
TIMEOUT = 2

def extract_domain(url: str) -> Optional[str]:
	text = url.strip()
	if not text:
		return None

	parsed = urlparse(text if "://" in text else "http://" + text)
	host = parsed.hostname
	if not host:
		return None

	return host.rstrip(".").lower()


def encode_qname(domain: str) -> bytes:
	result = bytearray()
	ascii_domain = domain.encode("idna").decode("ascii")

	for label in ascii_domain.split("."):
		if not label:
			continue
		data = label.encode("ascii")
		if len(data) > 63:
			raise ValueError(f"DNS label too long: {label!r}")
		result.append(len(data))
		result.extend(data)

	result.append(0)
	return bytes(result)


def skip_name(packet: bytes, offset: int) -> int:
	while True:
		if offset >= len(packet):
			raise ValueError("Malformed DNS packet while skipping name")

		length = packet[offset]

		if length & 0xC0 == 0xC0:
			return offset + 2

		if length == 0:
			return offset + 1

		offset += 1 + length


def resolve_a_records(domain: str, server: str, timeout: float = TIMEOUT) -> List[str]:
	qid = random.randrange(0, 65536)
	header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
	question = encode_qname(domain) + struct.pack("!HH", 1, 1)
	packet = header + question

	with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
		sock.settimeout(timeout)
		sock.sendto(packet, (server, 53))
		data, _ = sock.recvfrom(4096)

	if len(data) < 12:
		return []

	resp_id, flags, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", data[:12])

	if resp_id != qid:
		return []

	if (flags & 0x8000) == 0:
		return []

	if (flags & 0x000F) != 0:
		return []

	offset = 12

	for _ in range(qdcount):
		offset = skip_name(data, offset)
		offset += 4
		if offset > len(data):
			return []

	ips: List[str] = []

	for _ in range(ancount):
		offset = skip_name(data, offset)

		if offset + 10 > len(data):
			break

		rtype, rclass, _, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
		offset += 10

		if offset + rdlength > len(data):
			break

		rdata = data[offset:offset + rdlength]
		offset += rdlength

		if rtype == 1 and rclass == 1 and rdlength == 4:
			ips.append(socket.inet_ntoa(rdata))

	return sorted(set(ips))


async def resolve_domain(domain: str) -> Tuple[Dict[str, List[str]], bool]:
	loop = asyncio.get_running_loop()

	futures = [
		loop.run_in_executor(None, resolve_a_records, domain, server)
		for server in DNS_SERVERS
	]

	results = await asyncio.gather(*futures, return_exceptions=True)

	per_server: Dict[str, List[str]] = {}
	ip_sets = []

	for server, result in zip(DNS_SERVERS, results):
		if isinstance(result, Exception):
			per_server[server] = []
			continue

		per_server[server] = result
		ip_sets.append(tuple(result))

	static_ok = (
		len(ip_sets) == len(DNS_SERVERS)
		and len(ip_sets) > 0
		and len(set(ip_sets)) == 1
		and len(ip_sets[0]) > 0
	)

	return per_server, static_ok


async def test_port(domain: str, ips: List[str], port: int, use_ssl: bool) -> bool:
	if not ips:
		return False

	host = domain.encode("idna").decode("ascii")

	for ip in ips:
		reader = None
		writer = None

		try:
			if use_ssl:
				context = ssl.create_default_context()
				context.check_hostname = False
				context.verify_mode = ssl.CERT_NONE

				reader, writer = await asyncio.wait_for(
					asyncio.open_connection(
						ip,
						port,
						ssl=context,
						server_hostname=host,
					),
					timeout=TIMEOUT,
				)
			else:
				reader, writer = await asyncio.wait_for(
					asyncio.open_connection(ip, port),
					timeout=TIMEOUT,
				)

			request = (
				"HEAD / HTTP/1.1\r\n"
				f"Host: {host}\r\n"
				"Connection: close\r\n"
				"User-Agent: Python3\r\n\r\n"
			)

			writer.write(request.encode("ascii", "ignore"))
			await asyncio.wait_for(writer.drain(), timeout=TIMEOUT)

			data = await asyncio.wait_for(reader.read(64), timeout=TIMEOUT)

			if data.startswith(b"HTTP/"):
				return True

		except Exception:
			pass

		finally:
			if writer is not None:
				writer.close()
				try:
					await writer.wait_closed()
				except Exception:
					pass

	return False


async def process_domain(domain: str, semaphore: asyncio.Semaphore):
	async with semaphore:
		per_server, static_ok = await resolve_domain(domain)

		connect_ips: List[str] = []
		for server in DNS_SERVERS:
			if per_server.get(server):
				connect_ips = per_server[server]
				break

		http_ok = await test_port(domain, connect_ips, 80, False)
		https_ok = await test_port(domain, connect_ips, 443, True)

		return domain, http_ok, https_ok, static_ok


def parse_input_file(input_path: str) -> "OrderedDict[str, Dict[str, List[str]]]":
	try:
		with open(input_path, "r", encoding="utf-8", errors="ignore") as f:
			raw_lines = [line.strip() for line in f if line.strip()]
	except Exception as exc:
		print("Failed to read input file:", exc, file=sys.stderr)
		raise

	domain_urls: "OrderedDict[str, Dict[str, List[str]]]" = OrderedDict()

	for line in raw_lines:
		parsed = urlparse(line if "://" in line else "http://" + line)

		domain = parsed.hostname
		scheme = parsed.scheme.lower()

		if not domain:
			continue

		if scheme not in ("http", "https"):
			continue

		domain = domain.rstrip(".").lower()

		if domain not in domain_urls:
			domain_urls[domain] = {"http": [], "https": []}

		if line not in domain_urls[domain][scheme]:
			domain_urls[domain][scheme].append(line)

	return domain_urls


async def main() -> int:
	parser = argparse.ArgumentParser()
	parser.add_argument(
		"--only-static",
		action="store_true",
		help="Write only Static: Okay URLs to output",
	)
	args = parser.parse_args()

	input_path = input("Enter INPUT file path: ").strip()
	output_path = input("Enter OUTPUT file path: ").strip()

	try:
		domain_urls = parse_input_file(input_path)
	except Exception:
		return 1

	semaphore = asyncio.Semaphore(MAX_PARALLEL)

	tasks = [
		asyncio.create_task(process_domain(domain, semaphore))
		for domain in domain_urls
	]

	try:
		with open(output_path, "w", encoding="utf-8") as output_file:
			for task in asyncio.as_completed(tasks):
				domain, http_ok, https_ok, static_ok = await task

				print(f"{domain} [80: {'Okay' if http_ok else 'Fail'}]", flush=True)
				print(f"{domain} [443: {'Okay' if https_ok else 'Fail'}]", flush=True)
				print(f"{domain} [Static: {'Okay' if static_ok else 'Fail'}]", flush=True)

				should_write = http_ok and https_ok
				if args.only_static:
					should_write = should_write and static_ok

				if should_write:
					for line in domain_urls[domain]["http"]:
						output_file.write(line + "\n")
					for line in domain_urls[domain]["https"]:
						output_file.write(line + "\n")

					output_file.flush()

	except Exception as exc:
		print("Failed to write output file:", exc, file=sys.stderr)
		return 1

	return 0


if __name__ == "__main__":
	raise SystemExit(asyncio.run(main()))
