# VDI Hardening Scanner
# Tac gia: Quynh Ngo. Ho tro: Claude (Anthropic) qua Claude Code.
# Cap nhat: 2026-09-24. Lich su day du: git log -- <duong dan file>

"""Luu tru bang file JSON - khong dung database.

Toan bo trang thai nam trong thu muc data/, doc va sua duoc bang tay:

    data/settings.json      tham so chuan hardening
    data/credentials.json   thong tin dang nhap (KHONG chua mat khau)
    data/hosts.json         danh sach may chu
    data/marks.json         cac muc tick tay
    data/runs/<id>/         meta.json, run.log, results.json, reports/
"""
from __future__ import annotations

import json
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("HARDENING_DATA_DIR", ROOT / "data"))
RUNS_DIR = DATA_DIR / "runs"
CATALOG_FILE = ROOT / "catalog" / "checklist.json"
ANSIBLE_DIR = ROOT / "ansible"
WEB_DIR = ROOT / "frontend"

_lock = threading.RLock()

DEFAULT_SETTINGS: dict[str, Any] = {
    "timezone": "Asia/Ho_Chi_Minh",
    "ntp_servers": [],
    "log_servers": [],
    "internal_repo_hosts": [],
    "admin_networks": [],
    "admin_users": [],
    "business_users": [],
    "ssh_allow_groups": ["wheel"],
    "extra_firewall_rules": [],
    "nofile_min": 65535,
    "nproc_min": 8192,
    "conntrack_max_min": 524288,
    "conntrack_hashsize": 131072,
    "tmout": 300,
    "openssl_min_version": "1.1.1",
    "ssh_max_auth_tries": 3,
    "ssh_client_alive_interval": 300,
    "ssh_client_alive_count_max": 3,
    "unowned_scan": True,
    "unowned_scan_timeout": 120,
    "allow_reboot_changes": False,
    "remove_virtual_nic": True,
    "ansible_forks": 20,
}


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def ensure_dirs() -> None:
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(DATA_DIR, 0o700)
    except OSError:
        pass


# ------------------------------------------------------------------ doc / ghi


def _read(path: Path, fallback: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return fallback


def _write(path: Path, value: Any) -> None:
    """Ghi nguyen tu: ghi file tam roi doi ten, tranh mat du lieu khi dang ghi."""
    ensure_dirs()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)


# ------------------------------------------------------------------ settings


def get_settings() -> dict[str, Any]:
    with _lock:
        stored = _read(DATA_DIR / "settings.json", {})
    merged = dict(DEFAULT_SETTINGS)
    merged.update({k: v for k, v in stored.items() if k in DEFAULT_SETTINGS})
    return merged


def save_settings(values: dict[str, Any]) -> dict[str, Any]:
    with _lock:
        current = get_settings()
        current.update({k: v for k, v in values.items() if k in DEFAULT_SETTINGS})
        _write(DATA_DIR / "settings.json", current)
        return current


# ------------------------------------------------------------------ credentials
# Mat khau KHONG bao gio duoc ghi xuong dia - chi giu trong RAM cua tien trinh.

_SECRETS: dict[int, dict[str, str]] = {}


def list_credentials() -> list[dict[str, Any]]:
    with _lock:
        creds = _read(DATA_DIR / "credentials.json", [])
    for c in creds:
        c["unlocked"] = c["id"] in _SECRETS
        c["needs_password"] = c["auth_type"] == "password" and c["id"] not in _SECRETS
    return creds


def get_credential(cred_id: int) -> dict[str, Any] | None:
    for c in list_credentials():
        if c["id"] == cred_id:
            return c
    return None


def add_credential(data: dict[str, Any]) -> dict[str, Any]:
    with _lock:
        creds = _read(DATA_DIR / "credentials.json", [])
        if any(c["name"] == data["name"] for c in creds):
            raise ValueError(f"Da ton tai credential ten '{data['name']}'")
        cred = {
            "id": max([c["id"] for c in creds], default=0) + 1,
            "name": data["name"],
            "username": data["username"],
            "auth_type": data["auth_type"],
            "key_path": data.get("key_path") or None,
            "become_method": data.get("become_method") or "sudo",
            "port": int(data.get("port") or 22),
            "created_at": now_iso(),
        }
        creds.append(cred)
        _write(DATA_DIR / "credentials.json", creds)
    if data.get("password") or data.get("become_password"):
        unlock_credential(cred["id"], data.get("password"), data.get("become_password"))
    return cred


def delete_credential(cred_id: int) -> None:
    with _lock:
        creds = [c for c in _read(DATA_DIR / "credentials.json", []) if c["id"] != cred_id]
        _write(DATA_DIR / "credentials.json", creds)
        _SECRETS.pop(cred_id, None)
        hosts = _read(DATA_DIR / "hosts.json", [])
        for h in hosts:
            if h.get("credential_id") == cred_id:
                h["credential_id"] = None
        _write(DATA_DIR / "hosts.json", hosts)


def unlock_credential(cred_id: int, password: str | None, become_password: str | None) -> None:
    """Nap mat khau vao bo nho. Mat di khi tat tien trinh."""
    entry = _SECRETS.setdefault(cred_id, {})
    if password:
        entry["password"] = password
    if become_password:
        entry["become_password"] = become_password


def get_secret(cred_id: int) -> dict[str, str]:
    return _SECRETS.get(cred_id, {})


def locked_credentials(cred_ids: list[int]) -> list[dict[str, Any]]:
    """Cac credential kieu password nhung chua duoc nhap mat khau trong phien nay."""
    out = []
    for cid in set(cred_ids):
        cred = get_credential(cid)
        if cred and cred["auth_type"] == "password" and "password" not in get_secret(cid):
            out.append(cred)
    return out


# ------------------------------------------------------------------ hosts


def list_hosts() -> list[dict[str, Any]]:
    with _lock:
        hosts = _read(DATA_DIR / "hosts.json", [])
    names = {c["id"]: c["name"] for c in list_credentials()}
    for h in hosts:
        h["credential_name"] = names.get(h.get("credential_id"))
    return hosts


def get_hosts(ids: list[int]) -> list[dict[str, Any]]:
    wanted = set(ids)
    return [h for h in list_hosts() if h["id"] in wanted]


def _save_hosts(hosts: list[dict[str, Any]]) -> None:
    for h in hosts:
        h.pop("credential_name", None)
    _write(DATA_DIR / "hosts.json", hosts)


def add_host(ip: str, hostname: str | None = None, port: int = 22,
             credential_id: int | None = None, note: str | None = None) -> dict[str, Any]:
    with _lock:
        hosts = _read(DATA_DIR / "hosts.json", [])
        if any(h["ip"] == ip for h in hosts):
            raise ValueError(f"Host {ip} da ton tai")
        host = {
            "id": max([h["id"] for h in hosts], default=0) + 1,
            "ip": ip,
            "hostname": hostname,
            "port": port,
            "credential_id": credential_id,
            "note": note,
            "last_seen": None,
            "os_name": None,
            "created_at": now_iso(),
        }
        hosts.append(host)
        _save_hosts(hosts)
        return host


def upsert_discovered(ip: str, hostname: str | None, port: int, banner: str | None) -> bool:
    """Them host moi hoac cap nhat host da co. Tra ve True neu la host moi."""
    with _lock:
        hosts = _read(DATA_DIR / "hosts.json", [])
        for h in hosts:
            if h["ip"] == ip:
                h["hostname"] = hostname or h.get("hostname")
                h["port"] = port
                h["last_seen"] = now_iso()
                _save_hosts(hosts)
                return False
        hosts.append({
            "id": max([h["id"] for h in hosts], default=0) + 1,
            "ip": ip, "hostname": hostname, "port": port,
            "credential_id": None, "note": banner,
            "last_seen": now_iso(), "os_name": None, "created_at": now_iso(),
        })
        _save_hosts(hosts)
        return True


def delete_host(host_id: int) -> None:
    with _lock:
        hosts = [h for h in _read(DATA_DIR / "hosts.json", []) if h["id"] != host_id]
        _save_hosts(hosts)


def assign_credential(host_ids: list[int], credential_id: int | None) -> int:
    with _lock:
        hosts = _read(DATA_DIR / "hosts.json", [])
        wanted = set(host_ids)
        n = 0
        for h in hosts:
            if h["id"] in wanted:
                h["credential_id"] = credential_id
                n += 1
        _save_hosts(hosts)
        return n


def touch_host(ip: str, os_name: str | None) -> None:
    with _lock:
        hosts = _read(DATA_DIR / "hosts.json", [])
        for h in hosts:
            if h["ip"] == ip:
                h["last_seen"] = now_iso()
                if os_name:
                    h["os_name"] = os_name
        _save_hosts(hosts)


# ------------------------------------------------------------------ manual marks


def get_marks() -> dict[str, dict[str, Any]]:
    """Khoa dang '<ip>|<check_id>' de khong phu thuoc id noi bo."""
    with _lock:
        return _read(DATA_DIR / "marks.json", {})


def set_mark(ip: str, check_id: str, status: str, note: str | None) -> None:
    with _lock:
        marks = _read(DATA_DIR / "marks.json", {})
        key = f"{ip}|{check_id}"
        if status:
            marks[key] = {"status": status, "note": note, "updated_at": now_iso()}
        else:
            marks.pop(key, None)
        _write(DATA_DIR / "marks.json", marks)


# ------------------------------------------------------------------ runs


_RUN_RE = re.compile(r"^run-(\d+)$")


def next_run_id() -> int:
    with _lock:
        ensure_dirs()
        ids = [int(m.group(1)) for d in RUNS_DIR.iterdir()
               if d.is_dir() and (m := _RUN_RE.match(d.name))]
        return max(ids, default=0) + 1


def run_dir(run_id: int) -> Path:
    return RUNS_DIR / f"run-{run_id}"


def save_run_meta(run_id: int, meta: dict[str, Any]) -> None:
    _write(run_dir(run_id) / "meta.json", meta)


def get_run_meta(run_id: int) -> dict[str, Any] | None:
    meta = _read(run_dir(run_id) / "meta.json", None)
    return meta


def update_run_meta(run_id: int, **fields: Any) -> dict[str, Any]:
    with _lock:
        meta = get_run_meta(run_id) or {}
        meta.update(fields)
        save_run_meta(run_id, meta)
        return meta


def list_runs(limit: int = 100) -> list[dict[str, Any]]:
    ensure_dirs()
    out = []
    for d in RUNS_DIR.iterdir():
        if not d.is_dir() or not _RUN_RE.match(d.name):
            continue
        meta = _read(d / "meta.json", None)
        if meta:
            out.append(meta)
    out.sort(key=lambda m: m.get("id", 0), reverse=True)
    return out[:limit]


def save_results(run_id: int, hosts: list[dict[str, Any]]) -> None:
    _write(run_dir(run_id) / "results.json", {"hosts": hosts})


def get_results(run_id: int) -> list[dict[str, Any]]:
    return _read(run_dir(run_id) / "results.json", {"hosts": []}).get("hosts", [])


def read_log(run_id: int) -> list[str]:
    path = run_dir(run_id) / "run.log"
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


# ------------------------------------------------------------------ catalog

_catalog_cache: dict[str, Any] | None = None


def catalog() -> dict[str, Any]:
    global _catalog_cache
    if _catalog_cache is None:
        _catalog_cache = json.loads(CATALOG_FILE.read_text(encoding="utf-8"))
    return _catalog_cache


def checks_by_id() -> dict[str, dict[str, Any]]:
    return {c["id"]: c for c in catalog()["checks"]}


def remediable_ids() -> list[str]:
    return [c["id"] for c in catalog()["checks"] if c.get("remediable")]
