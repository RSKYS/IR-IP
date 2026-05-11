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
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

MAX_PARALLEL = 25
TIMEOUT = 2

PORTS: tuple[tuple[str, int], ...] = (
	("HTTP", 80),
	("HTTPS", 443),
)


def prompt_path(message: str) -> Path:
	return Path(input(message).strip().strip('"').strip("'")).expanduser()


def ask_file_paths() -> tuple[Path, Path, Path, Path]:
	input_path = prompt_path("Enter INPUT file path of URLs: ")
	mirror202_path = prompt_path("Enter OUTPUT path for Mirrors: ")
	host202_path = prompt_path("Enter OUTPUT path for Host: ")
	ip202_path = prompt_path("Enter OUTPUT path for IPs: ")
	return input_path, mirror202_path, host202_path, ip202_path


def extract_clean_url(line: str) -> str:
	text = (line or "").strip()
	if not text:
		return ""
	return text.split(None, 1)[0].strip()


def normalize_targets(text: str) -> list[str]:
	text = (text or "").strip()
	if not text:
		return []

	candidate = text if "://" in text else f"http://{text}"
	host: str | None = None

	try:
		parsed = urlparse(candidate)
		host = parsed.hostname
	except Exception:
		host = None

	if not host:
		raw = text.split("/", 1)[0].split("@")[-1]
		if raw.startswith("[") and "]" in raw:
			host = raw[1 : raw.index("]")]
		else:
			host = raw.split(":", 1)[0]

	host = (host or "").strip()
	if host.startswith("[") and host.endswith("]"):
		host = host[1:-1]

	if not host:
		return []

	if host.startswith("*."):
		base = host[2:]
		return [base, f"www.{base}"]

	return [host]


def build_suffix(source_text: str) -> str:
	text = (source_text or "").strip()
	if not text:
		return ""

	if "://" in text:
		parsed = urlparse(text)
		suffix = ""
		if parsed.path:
			suffix += parsed.path
		if parsed.query:
			suffix += f"?{parsed.query}"
		if parsed.fragment:
			suffix += f"#{parsed.fragment}"
		return suffix

	if "/" in text:
		return "/" + text.split("/", 1)[1].lstrip("/")

	return ""


def make_url(scheme: str, host: str, suffix: str) -> str:
	return f"{scheme}://{host}{suffix}"


def unique_preserve_order(items: list[str]) -> list[str]:
	seen: set[str] = set()
	output: list[str] = []
	for item in items:
		if item not in seen:
			seen.add(item)
			output.append(item)
	return output


def try_connect(host: str, port: int, timeout: float) -> tuple[bool, str | None]:
	try:
		with socket.create_connection((host, port), timeout=timeout):
			return True, None
	except socket.timeout:
		return False, "timeout"
	except ConnectionRefusedError:
		return False, "connection refused"
	except socket.gaierror as e:
		return False, f"DNS error: {e}"
	except OSError as e:
		return False, str(e)
	except Exception as e:
		return False, f"unexpected error: {e}"


def resolve_first_ip(host: str) -> str | None:
	try:
		infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
	except Exception:
		return None

	for _, _, _, _, sockaddr in infos:
		try:
			ip = sockaddr[0]
			if ip:
				return ip
		except Exception:
			continue
	return None


def check_host(host: str, timeout: float) -> tuple[dict[str, bool], list[str]]:
	results: dict[str, bool] = {}
	notes: list[str] = []

	for label, port in PORTS:
		ok, err = try_connect(host, port, timeout)
		results[label] = ok
		if not ok and err:
			notes.append(f"{label}: {err}")

	return results, notes


class ConcurrentMemo:
	def __init__(self) -> None:
		self._lock = threading.Lock()
		self._values: dict[str, Any] = {}
		self._events: dict[str, threading.Event] = {}

	def get_or_compute(self, key: str, factory: Callable[[], Any]) -> Any:
		with self._lock:
			if key in self._values:
				value = self._values[key]
				if isinstance(value, BaseException):
					raise value
				return value

			event = self._events.get(key)
			if event is None:
				event = threading.Event()
				self._events[key] = event
				owner = True
			else:
				owner = False

		if not owner:
			event.wait()
			with self._lock:
				value = self._values[key]
			if isinstance(value, BaseException):
				raise value
			return value

		value: Any = None
		raised: BaseException | None = None
		try:
			value = factory()
		except BaseException as exc:
			value = exc
			raised = exc
		finally:
			with self._lock:
				self._values[key] = value
				finished = self._events.pop(key, None)
				if finished is not None:
					finished.set()

		if raised is not None:
			raise raised
		return value


@dataclass(slots=True)
class ProcessResult:
	index: int
	mirror202_lines: list[str]
	host202_lines: list[str]
	ip202_lines: list[str]
	messages: list[str]


def process_line(
	item: tuple[int, str, str, list[str]],
	timeout: float,
	host_cache: ConcurrentMemo,
	ip_cache: ConcurrentMemo,
) -> ProcessResult | None:
	index, _raw_line, clean_url, hosts = item
	if not clean_url or not hosts:
		return None

	suffix = build_suffix(clean_url)

	mirror202_lines: list[str] = []
	host202_lines: list[str] = []
	ip202_lines: list[str] = []
	messages: list[str] = []

	for host in hosts:
		results, _notes = host_cache.get_or_compute(
			host,
			lambda host=host: check_host(host, timeout),
		)

		http_ok = results.get("HTTP", False)
		https_ok = results.get("HTTPS", False)

		open_ports = [label for label, ok in (("HTTP", http_ok), ("HTTPS", https_ok)) if ok]
		if not open_ports:
			continue

		messages.append(f"[CHECKED] {host} -> {', '.join(open_ports)}")

		if http_ok:
			mirror202_lines.append(make_url("http", host, suffix))

		if https_ok:
			mirror202_lines.append(make_url("https", host, suffix))

		ip = ip_cache.get_or_compute(
			host,
			lambda host=host: resolve_first_ip(host),
		)
		if ip:
			host202_lines.append(f"{ip} {host}")
			ip202_lines.append(ip)

	mirror202_lines = unique_preserve_order(mirror202_lines)
	host202_lines = unique_preserve_order(host202_lines)
	ip202_lines = unique_preserve_order(ip202_lines)

	if not mirror202_lines:
		return None

	return ProcessResult(
		index=index,
		mirror202_lines=mirror202_lines,
		host202_lines=host202_lines,
		ip202_lines=ip202_lines,
		messages=messages,
	)


def main() -> int:
	input_file, mirror202_file, host202_file, ip202_file = ask_file_paths()

	print()
	print(f"Input       : {input_file}")
	print(f"Mirror 202   : {mirror202_file}")
	print(f"Host 202     : {host202_file}")
	print(f"IP 202       : {ip202_file}")
	print()

	if not input_file.exists():
		print(f"ERROR: File not found -> {input_file}")
		return 1

	try:
		lines = input_file.read_text(encoding="utf-8", errors="ignore").splitlines()
	except Exception as e:
		print(f"ERROR reading input file: {e}")
		return 1

	mirror202_file.parent.mkdir(parents=True, exist_ok=True)
	host202_file.parent.mkdir(parents=True, exist_ok=True)
	ip202_file.parent.mkdir(parents=True, exist_ok=True)

	work_items: list[tuple[int, str, str, list[str]]] = []
	for idx, raw_line in enumerate(lines):
		clean = extract_clean_url(raw_line)
		hosts = normalize_targets(clean)
		if clean and hosts:
			work_items.append((idx, raw_line, clean, hosts))

	if not work_items:
		print("No usable targets found.")
		mirror202_file.write_text("", encoding="utf-8")
		host202_file.write_text("", encoding="utf-8")
		ip202_file.write_text("", encoding="utf-8")
		return 0

	host_cache = ConcurrentMemo()
	ip_cache = ConcurrentMemo()

	# Check up to this many URLs at the same time.
	max_workers = min(MAX_PARALLEL, len(work_items))

	try:
		with (
			mirror202_file.open("w", encoding="utf-8", newline="\n") as out_mirror,
			host202_file.open("w", encoding="utf-8", newline="\n") as out_host,
			ip202_file.open("w", encoding="utf-8", newline="\n") as out_ip,
			ThreadPoolExecutor(max_workers=max_workers) as executor,
		):
			for result in executor.map(
				lambda item: process_line(item, TIMEOUT, host_cache, ip_cache),
				work_items,
			):
				if result is None:
					continue

				for msg in result.messages:
					print(msg)

				for line in result.mirror202_lines:
					out_mirror.write(line + "\n")
				for line in result.host202_lines:
					out_host.write(line + "\n")
				for line in result.ip202_lines:
					out_ip.write(line + "\n")

		print("\nDone.")
		print(f"Results saved to: {mirror202_file}")
		return 0

	except KeyboardInterrupt:
		print("\nInterrupted.")
		return 130
	except Exception as e:
		print(f"\nUnexpected error: {e}")
		return 1


if __name__ == "__main__":
	raise SystemExit(main())
