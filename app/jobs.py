# VDI Hardening Scanner
# Tac gia: Quynh Ngo. Ho tro: Claude (Anthropic) qua Claude Code.
# Cap nhat: 2026-09-24. Lich su day du: git log -- <duong dan file>

"""Chay ansible-playbook / quet dai IP duoi dang job nen, khong dung asyncio."""
from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import threading
from pathlib import Path
from typing import Any

from . import discovery, store


class Job:
    """Mot lan chay. Log giu trong bo nho de SSE doc theo chi so."""

    def __init__(self, run_id: int, kind: str) -> None:
        self.run_id = run_id
        self.kind = kind
        self.lines: list[str] = []
        self.finished = False
        self.process: subprocess.Popen | None = None
        self.cancelled = False
        self._log_file = None

    def emit(self, text: str) -> None:
        self.lines.append(text)
        if self._log_file:
            try:
                self._log_file.write(text + "\n")
                self._log_file.flush()
            except OSError:
                pass

    def stop_requested(self) -> bool:
        return self.cancelled


_jobs: dict[int, Job] = {}
_jobs_lock = threading.Lock()


def get_job(run_id: int) -> Job | None:
    with _jobs_lock:
        return _jobs.get(run_id)


def _register(job: Job) -> None:
    with _jobs_lock:
        _jobs[job.run_id] = job
        # Chi giu log trong RAM cho 20 lan chay gan nhat
        if len(_jobs) > 20:
            for rid in sorted(_jobs)[:-20]:
                if _jobs[rid].finished:
                    del _jobs[rid]


# ------------------------------------------------------------------ sinh cau hinh


def build_audit_config(settings: dict[str, Any]) -> str:
    payload = {
        "timezone": settings["timezone"],
        "ntp_servers": settings["ntp_servers"],
        "ntp_min_servers": 2,
        "nofile_min": settings["nofile_min"],
        "nproc_min": settings["nproc_min"],
        "conntrack_max_min": settings["conntrack_max_min"],
        "conntrack_hashsize": settings["conntrack_hashsize"],
        "tmout": settings["tmout"],
        "ssh_max_auth_tries": settings["ssh_max_auth_tries"],
        "ssh_client_alive_interval": settings["ssh_client_alive_interval"],
        "ssh_client_alive_count_max": settings["ssh_client_alive_count_max"],
        "openssl_min_version": settings["openssl_min_version"],
        "log_servers": settings["log_servers"],
        "internal_repo_hosts": settings["internal_repo_hosts"],
        "admin_networks": settings["admin_networks"],
        "business_users": settings["business_users"],
        "unowned_scan": settings["unowned_scan"],
        "unowned_scan_timeout": settings["unowned_scan_timeout"],
    }
    return base64.b64encode(json.dumps(payload, ensure_ascii=False).encode("utf-8")).decode("ascii")


def build_harden_vars(settings: dict[str, Any]) -> dict[str, Any]:
    return {
        "harden_timezone": settings["timezone"],
        "harden_ntp_servers": settings["ntp_servers"],
        "harden_nofile": settings["nofile_min"],
        "harden_nproc": settings["nproc_min"],
        "harden_conntrack_max": settings["conntrack_max_min"],
        "harden_conntrack_hashsize": settings["conntrack_hashsize"],
        "harden_tmout": settings["tmout"],
        "harden_admin_users": settings["admin_users"],
        "harden_business_users": settings["business_users"],
        "harden_ssh_allow_groups": settings["ssh_allow_groups"],
        "harden_admin_networks": settings["admin_networks"],
        "harden_extra_firewall_rules": settings["extra_firewall_rules"],
        "harden_log_servers": settings["log_servers"],
        "harden_internal_repo_hosts": settings["internal_repo_hosts"],
        "harden_allow_reboot_changes": settings["allow_reboot_changes"],
        "harden_remove_virtual_nic": settings["remove_virtual_nic"],
        "harden_ssh_max_auth_tries": settings["ssh_max_auth_tries"],
        "harden_ssh_client_alive_interval": settings["ssh_client_alive_interval"],
        "harden_ssh_client_alive_count_max": settings["ssh_client_alive_count_max"],
    }


def build_inventory(hosts: list[dict[str, Any]]) -> tuple[dict[str, Any], list[str]]:
    """Sinh inventory dang JSON (JSON la YAML hop le nen Ansible doc duoc)."""
    entries: dict[str, Any] = {}
    missing: list[str] = []

    for h in hosts:
        cred = store.get_credential(h.get("credential_id")) if h.get("credential_id") else None
        if cred is None:
            missing.append(h["ip"])
            continue

        secret = store.get_secret(cred["id"])
        hvars: dict[str, Any] = {
            "ansible_host": h["ip"],
            "ansible_port": h.get("port") or cred.get("port") or 22,
            "ansible_user": cred["username"],
            "ansible_become": True,
            "ansible_become_method": cred.get("become_method") or "sudo",
        }

        if cred["auth_type"] == "key":
            if cred.get("key_path"):
                hvars["ansible_ssh_private_key_file"] = os.path.expanduser(cred["key_path"])
        elif secret.get("password"):
            hvars["ansible_password"] = secret["password"]
        else:
            missing.append(h["ip"])
            continue

        become_pw = secret.get("become_password") or secret.get("password")
        if become_pw:
            hvars["ansible_become_password"] = become_pw

        entries[h["ip"]] = hvars

    return {"all": {"children": {"targets": {"hosts": entries}}}}, missing


# ------------------------------------------------------------------ job: do tim


def start_discovery(spec: str, port: int = 22, resolve_names: bool = True) -> int:
    hosts = discovery.parse_spec(spec)
    run_id = store.next_run_id()
    store.run_dir(run_id).mkdir(parents=True, exist_ok=True)
    store.save_run_meta(run_id, {
        "id": run_id, "kind": "discovery", "status": "running",
        "created_at": store.now_iso(), "started_at": store.now_iso(),
        "finished_at": None, "rc": None, "message": None,
        "check_ids": [], "host_ips": [],
    })

    job = Job(run_id, "discovery")
    _register(job)
    threading.Thread(
        target=_run_discovery, args=(job, hosts, port, resolve_names), daemon=True
    ).start()
    return run_id


def _run_discovery(job: Job, hosts: list[str], port: int, resolve_names: bool) -> None:
    job._log_file = (store.run_dir(job.run_id) / "run.log").open("w", encoding="utf-8")
    job.emit(f"Bat dau quet {len(hosts)} dia chi tren cong {port}...")
    rc, message = 0, None
    try:
        results = discovery.scan(
            hosts, port=port, resolve_names=resolve_names,
            progress=lambda d, t, f: job.emit(f"Da quet {d}/{t} - tim thay {f} host mo cong {port}"),
            should_stop=job.stop_requested,
        )
        added = sum(1 for r in results
                    if store.upsert_discovered(r["ip"], r.get("hostname"), port, r.get("banner")))
        job.emit(f"Hoan tat: tim thay {len(results)} host, them moi {added}, "
                 f"cap nhat {len(results) - added}.")
        if job.cancelled:
            rc, message = 3, "Nguoi dung da dung giua chung"
    except discovery.TargetSpecError as exc:
        rc, message = 2, str(exc)
        job.emit("LOI: " + message)
    except Exception as exc:  # noqa: BLE001
        rc, message = 1, str(exc)
        job.emit("LOI: " + message)
    _finish(job, rc, message)


# ------------------------------------------------------------------ job: audit / remediate


def start_scan(kind: str, host_ids: list[int], check_ids: list[str] | None = None) -> int:
    if kind not in ("audit", "remediate"):
        raise ValueError("kind phai la 'audit' hoac 'remediate'")
    hosts = store.get_hosts(host_ids)
    if not hosts:
        raise ValueError("Chua chon may chu nao.")

    run_id = store.next_run_id()
    store.run_dir(run_id).mkdir(parents=True, exist_ok=True)
    store.save_run_meta(run_id, {
        "id": run_id, "kind": kind, "status": "running",
        "created_at": store.now_iso(), "started_at": store.now_iso(),
        "finished_at": None, "rc": None, "message": None,
        "check_ids": check_ids or [], "host_ips": [h["ip"] for h in hosts],
    })

    job = Job(run_id, kind)
    _register(job)
    threading.Thread(target=_run_scan, args=(job, hosts, check_ids or []), daemon=True).start()
    return run_id


def _run_scan(job: Job, hosts: list[dict[str, Any]], check_ids: list[str]) -> None:
    run_dir = store.run_dir(job.run_id)
    report_dir = run_dir / "reports"
    report_dir.mkdir(exist_ok=True)
    inventory_file = run_dir / "inventory.yml"
    extra_file = run_dir / "extravars.json"

    job._log_file = (run_dir / "run.log").open("w", encoding="utf-8")
    settings = store.get_settings()
    inventory, missing = build_inventory(hosts)

    if missing:
        job.emit("CANH BAO: cac host sau chua co thong tin dang nhap day du va bi bo qua: "
                 + ", ".join(missing))
    if not inventory["all"]["children"]["targets"]["hosts"]:
        job.emit("LOI: khong co host nao san sang de chay.")
        _finish(job, 2, "Khong co host hop le")
        return

    # JSON la tap con cua YAML nen Ansible doc duoc, va json.dump lo escape ho.
    inventory_file.write_text(json.dumps(inventory, ensure_ascii=False, indent=2), encoding="utf-8")
    os.chmod(inventory_file, 0o600)

    extra = build_harden_vars(settings)
    extra["report_dir"] = str(report_dir)
    extra["audit_config_b64"] = build_audit_config(settings)
    extra_file.write_text(json.dumps(extra, ensure_ascii=False), encoding="utf-8")
    os.chmod(extra_file, 0o600)

    playbook = "audit.yml" if job.kind == "audit" else "remediate.yml"
    cmd = [
        "ansible-playbook",
        "-i", str(inventory_file),
        playbook,
        "-e", f"@{extra_file}",
        "--forks", str(settings.get("ansible_forks", 20)),
    ]
    if job.kind == "remediate" and check_ids:
        cmd += ["--tags", ",".join(check_ids)]

    env = dict(os.environ)
    env["ANSIBLE_CONFIG"] = str(store.ANSIBLE_DIR / "ansible.cfg")
    env["ANSIBLE_FORCE_COLOR"] = "0"
    env["PYTHONUNBUFFERED"] = "1"
    env["REPORT_DIR"] = str(report_dir)

    job.emit("$ " + " ".join(cmd))

    rc, message = -1, None
    try:
        proc = subprocess.Popen(
            cmd, cwd=str(store.ANSIBLE_DIR), env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )
        job.process = proc
        assert proc.stdout is not None
        for line in proc.stdout:
            job.emit(line.rstrip("\n"))
        rc = proc.wait()
    except FileNotFoundError:
        message = ("Khong tim thay lenh ansible-playbook. Cai bang: "
                   "pip install ansible-core  (hoac apt install ansible)")
        job.emit("LOI: " + message)
    except Exception as exc:  # noqa: BLE001
        message = f"Loi khi chay ansible: {exc}"
        job.emit("LOI: " + message)

    try:
        _ingest_reports(job.run_id, report_dir)
    except Exception as exc:  # noqa: BLE001
        job.emit(f"LOI khi doc report: {exc}")

    # Xoa file chua mat khau
    for path in (inventory_file, extra_file):
        try:
            path.unlink()
        except OSError:
            pass

    _finish(job, rc, message)


def _ingest_reports(run_id: int, report_dir: Path) -> None:
    """Gom cac file report tren controller thanh results.json chuan hoa."""
    hosts_out: list[dict[str, Any]] = []
    for path in sorted(report_dir.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue

        # 'host' la inventory_hostname - chinh la IP do tool sinh ra, nen dung
        # lam khoa. 'ansible_host' co the bi connection plugin ghi de.
        ip = data.get("host") or data.get("ansible_host") or path.stem
        payload = data.get("payload") or {}
        facts = payload.get("facts") or {}
        ok = bool(data.get("ok"))

        hosts_out.append({
            "ip": ip,
            "ok": ok,
            "error": data.get("error"),
            "facts": facts,
            "results": payload.get("results", []),
        })
        if ok:
            store.touch_host(ip, facts.get("os_name"))

    hosts_out.sort(key=lambda h: h["ip"])
    store.save_results(run_id, hosts_out)


def _finish(job: Job, rc: int, message: str | None) -> None:
    # ansible-playbook: 0 = thanh cong, 2 = mot so host that bai, 4 = khong ket noi duoc
    if rc == 0:
        status = "done"
    elif rc in (2, 4):
        status = "partial"
    else:
        status = "failed"
    store.update_run_meta(job.run_id, status=status, rc=rc, message=message,
                          finished_at=store.now_iso())
    job.finished = True
    job.emit(f"__JOB_END__ status={status} rc={rc}")
    if job._log_file:
        try:
            job._log_file.close()
        except OSError:
            pass
        job._log_file = None


def cancel(run_id: int) -> bool:
    job = get_job(run_id)
    if not job or job.finished:
        return False
    job.cancelled = True
    if job.process:
        try:
            job.process.terminate()
        except ProcessLookupError:
            return False
    job.emit("Da gui tin hieu dung...")
    return True


def ansible_available() -> bool:
    return shutil.which("ansible-playbook") is not None


def sshpass_available() -> bool:
    return shutil.which("sshpass") is not None
