# VDI Hardening Scanner
# Tac gia: Quynh Ngo. Ho tro: Claude (Anthropic) qua Claude Code.
# Cap nhat: 2026-09-24. Lich su day du: git log -- <duong dan file>

"""Phan giai dai IP va quet tim host mo cong SSH (chi dung thu vien chuan)."""
from __future__ import annotations

import ipaddress
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Iterable

MAX_HOSTS = 4096
CONCURRENCY = 128
TIMEOUT = 1.5


class TargetSpecError(ValueError):
    """Chuoi khai bao dai IP khong hop le."""


_SEP = re.compile(r"[,\s;]+")
_SHORT_RANGE = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})-(\d{1,3})$")


def parse_spec(spec: str, max_hosts: int = MAX_HOSTS) -> list[str]:
    """IP don, CIDR, dai ngan (192.168.1.10-40), dai day du, hoac hostname."""
    out: list[str] = []
    seen: set[str] = set()

    def add(value: str) -> None:
        if value in seen:
            return
        seen.add(value)
        out.append(value)
        if len(out) > max_hosts:
            raise TargetSpecError(
                f"Vuot qua gioi han {max_hosts} dia chi cho mot lan quet. Hay chia nho dai IP."
            )

    for token in _SEP.split((spec or "").strip()):
        if not token:
            continue

        if "/" in token:
            try:
                net = ipaddress.ip_network(token, strict=False)
            except ValueError as exc:
                raise TargetSpecError(f"CIDR khong hop le: {token}") from exc
            hosts: Iterable = net.hosts() if net.num_addresses > 2 else net
            for ip in hosts:
                add(str(ip))
            continue

        m = _SHORT_RANGE.match(token)
        if m:
            prefix, start, end = m.group(1), int(m.group(2)), int(m.group(3))
            if not (0 <= start <= 255 and 0 <= end <= 255):
                raise TargetSpecError(f"Octet ngoai khoang 0-255: {token}")
            if start > end:
                raise TargetSpecError(f"Dai IP nguoc: {token}")
            for i in range(start, end + 1):
                add(f"{prefix}.{i}")
            continue

        if "-" in token:
            left, _, right = token.partition("-")
            try:
                a = ipaddress.ip_address(left.strip())
                b = ipaddress.ip_address(right.strip())
            except ValueError as exc:
                raise TargetSpecError(f"Dai IP khong hop le: {token}") from exc
            if int(b) < int(a):
                raise TargetSpecError(f"Dai IP nguoc: {token}")
            for value in range(int(a), int(b) + 1):
                add(str(ipaddress.ip_address(value)))
            continue

        try:
            ipaddress.ip_address(token)
        except ValueError:
            pass  # coi la hostname
        add(token)

    if not out:
        raise TargetSpecError("Chua khai bao IP hoac dai IP nao.")
    return out


def _probe(host: str, port: int, timeout: float) -> dict | None:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(min(timeout, 2.0))
            try:
                banner = sock.recv(128).decode("utf-8", "replace").strip().splitlines()[0]
            except (OSError, IndexError):
                banner = ""
            return {"ip": host, "port": port, "banner": banner[:200]}
    except (OSError, socket.timeout):
        return None


def _resolve(ip: str) -> str | None:
    try:
        socket.setdefaulttimeout(2.0)
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return None


def _sort_key(item: dict):
    try:
        return (0, int(ipaddress.ip_address(item["ip"])))
    except ValueError:
        return (1, item["ip"])


def scan(
    hosts: list[str],
    port: int = 22,
    timeout: float = TIMEOUT,
    concurrency: int = CONCURRENCY,
    resolve_names: bool = True,
    progress: Callable[[int, int, int], None] | None = None,
    should_stop: Callable[[], bool] | None = None,
) -> list[dict]:
    found: list[dict] = []
    total = len(hosts)
    done = 0

    with ThreadPoolExecutor(max_workers=min(concurrency, max(total, 1))) as pool:
        futures = {pool.submit(_probe, h, port, timeout): h for h in hosts}
        for fut in as_completed(futures):
            if should_stop and should_stop():
                for f in futures:
                    f.cancel()
                break
            result = fut.result()
            done += 1
            if result:
                found.append(result)
            if progress and (done % 25 == 0 or done == total):
                progress(done, total, len(found))

    if resolve_names and found:
        with ThreadPoolExecutor(max_workers=min(32, len(found))) as pool:
            names = list(pool.map(lambda f: _resolve(f["ip"]), found))
        for item, name in zip(found, names):
            item["hostname"] = name

    found.sort(key=_sort_key)
    return found
