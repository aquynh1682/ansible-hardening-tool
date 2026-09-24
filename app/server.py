# VDI Hardening Scanner
# Tac gia: Quynh Ngo. Ho tro: Claude (Anthropic) qua Claude Code.
# Cap nhat: 2026-09-24. Lich su day du: git log -- <duong dan file>

"""May chu HTTP nho dung thu vien chuan Python - khong can framework."""
from __future__ import annotations

import json
import mimetypes
import re
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

from . import discovery, jobs, reports, store


class HttpError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


Handler = Callable[..., Any]
ROUTES: list[tuple[str, re.Pattern, Handler]] = []


def route(method: str, pattern: str) -> Callable[[Handler], Handler]:
    def deco(fn: Handler) -> Handler:
        ROUTES.append((method, re.compile("^" + pattern + "$"), fn))
        return fn
    return deco


# ==================================================================== API


@route("GET", r"/api/health")
def api_health(req, _m):
    return {
        "ok": True,
        "ansible": jobs.ansible_available(),
        "sshpass": jobs.sshpass_available(),
        "checks": len(store.catalog()["checks"]),
        "data_dir": str(store.DATA_DIR),
    }


@route("GET", r"/api/checklist")
def api_checklist(req, _m):
    cat = store.catalog()
    return {
        "version": cat["version"],
        "sections": cat["sections"],
        "checks": cat["checks"],
        "remediable": store.remediable_ids(),
    }


@route("GET", r"/api/settings")
def api_get_settings(req, _m):
    return store.get_settings()


@route("PUT", r"/api/settings")
def api_put_settings(req, _m):
    return store.save_settings(req.json_body())


# ------------------------------------------------------------------ credentials


@route("GET", r"/api/credentials")
def api_list_credentials(req, _m):
    return store.list_credentials()


@route("POST", r"/api/credentials")
def api_add_credential(req, _m):
    body = req.json_body()
    for field in ("name", "username", "auth_type"):
        if not body.get(field):
            raise HttpError(400, f"Thieu truong bat buoc: {field}")
    if body["auth_type"] not in ("key", "password"):
        raise HttpError(400, "auth_type phai la 'key' hoac 'password'")

    if body["auth_type"] == "key":
        key_path = (body.get("key_path") or "").strip()
        if not key_path:
            raise HttpError(400, "Kieu 'key' can duong dan toi private key tren may nay.")
        resolved = Path(key_path).expanduser()
        if not resolved.is_file():
            raise HttpError(400, f"Khong tim thay file key: {resolved}")
        body["key_path"] = str(resolved)
    elif not body.get("password"):
        raise HttpError(400, "Kieu 'password' can mat khau.")

    try:
        return store.add_credential(body)
    except ValueError as exc:
        raise HttpError(409, str(exc)) from exc


@route("POST", r"/api/credentials/(\d+)/unlock")
def api_unlock_credential(req, m):
    body = req.json_body()
    cred_id = int(m.group(1))
    if store.get_credential(cred_id) is None:
        raise HttpError(404, "Khong tim thay credential")
    if not body.get("password") and not body.get("become_password"):
        raise HttpError(400, "Chua nhap mat khau")
    store.unlock_credential(cred_id, body.get("password"), body.get("become_password"))
    return {"unlocked": cred_id}


@route("DELETE", r"/api/credentials/(\d+)")
def api_delete_credential(req, m):
    store.delete_credential(int(m.group(1)))
    return {"deleted": int(m.group(1))}


# ------------------------------------------------------------------ hosts


@route("GET", r"/api/targets")
def api_list_targets(req, _m):
    return store.list_hosts()


@route("POST", r"/api/targets")
def api_add_target(req, _m):
    body = req.json_body()
    ip = (body.get("ip") or "").strip()
    if not ip:
        raise HttpError(400, "Chua nhap IP hoac hostname")
    try:
        return store.add_host(ip, body.get("hostname"), int(body.get("port") or 22),
                              body.get("credential_id"), body.get("note"))
    except ValueError as exc:
        raise HttpError(409, str(exc)) from exc


@route("POST", r"/api/targets/assign-credential")
def api_assign_credential(req, _m):
    body = req.json_body()
    ids = body.get("target_ids") or []
    if not ids:
        raise HttpError(400, "Chua chon may chu nao")
    n = store.assign_credential([int(i) for i in ids], body.get("credential_id"))
    return {"updated": n}


@route("DELETE", r"/api/targets/(\d+)")
def api_delete_target(req, m):
    store.delete_host(int(m.group(1)))
    return {"deleted": int(m.group(1))}


# ------------------------------------------------------------------ discovery


@route("POST", r"/api/discovery/preview")
def api_preview(req, _m):
    try:
        hosts = discovery.parse_spec(req.json_body().get("spec", ""))
    except discovery.TargetSpecError as exc:
        raise HttpError(400, str(exc)) from exc
    return {"count": len(hosts), "sample": hosts[:20]}


@route("POST", r"/api/discovery")
def api_discovery(req, _m):
    body = req.json_body()
    try:
        run_id = jobs.start_discovery(
            body.get("spec", ""), int(body.get("port") or 22),
            bool(body.get("resolve_names", True)),
        )
    except discovery.TargetSpecError as exc:
        raise HttpError(400, str(exc)) from exc
    return {"scan_id": run_id}


# ------------------------------------------------------------------ scans


@route("GET", r"/api/scans")
def api_list_scans(req, _m):
    return store.list_runs()


@route("POST", r"/api/scans")
def api_create_scan(req, _m):
    body = req.json_body()
    kind = body.get("kind")
    host_ids = [int(i) for i in (body.get("target_ids") or [])]
    check_ids = body.get("check_ids") or []

    if kind not in ("audit", "remediate"):
        raise HttpError(400, "kind phai la 'audit' hoac 'remediate'")
    if kind == "remediate":
        valid = set(store.remediable_ids())
        unknown = [c for c in check_ids if c not in valid]
        if unknown:
            raise HttpError(400, f"Cac muc sau khong ho tro tu dong khac phuc: {unknown}")
        if not check_ids:
            raise HttpError(400, "Chua chon muc hardening nao de trien khai.")

    hosts = store.get_hosts(host_ids)
    if not hosts:
        raise HttpError(400, "Chua chon may chu nao.")

    no_cred = [h["ip"] for h in hosts if not h.get("credential_id")]
    if no_cred:
        raise HttpError(400, "Cac host sau chua gan credential: " + ", ".join(no_cred))

    locked = store.locked_credentials([h["credential_id"] for h in hosts])
    if locked:
        raise HttpError(423, json.dumps({
            "reason": "locked_credentials",
            "credentials": [{"id": c["id"], "name": c["name"], "username": c["username"]}
                            for c in locked],
        }))

    try:
        run_id = jobs.start_scan(kind, host_ids, check_ids)
    except ValueError as exc:
        raise HttpError(400, str(exc)) from exc
    return {"scan_id": run_id}


@route("GET", r"/api/scans/(\d+)")
def api_get_scan(req, m):
    detail = reports.scan_detail(int(m.group(1)))
    if detail is None:
        raise HttpError(404, "Khong tim thay lan chay")
    return detail


@route("POST", r"/api/scans/(\d+)/cancel")
def api_cancel_scan(req, m):
    if not jobs.cancel(int(m.group(1))):
        raise HttpError(409, "Lan chay nay khong con dang chay")
    return {"cancelled": int(m.group(1))}


@route("GET", r"/api/scans/(\d+)/log")
def api_scan_log(req, m):
    run_id = int(m.group(1))
    job = jobs.get_job(run_id)
    if job:
        return {"lines": list(job.lines), "finished": job.finished}
    return {"lines": store.read_log(run_id), "finished": True}


@route("GET", r"/api/scans/(\d+)/report\.json")
def api_report_json(req, m):
    return api_get_scan(req, m)


@route("GET", r"/api/compare")
def api_compare(req, _m):
    try:
        before = int(req.query.get("before", [""])[0])
        after = int(req.query.get("after", [""])[0])
    except (TypeError, ValueError) as exc:
        raise HttpError(400, "Can tham so before va after") from exc
    result = reports.compare(before, after)
    if result is None:
        raise HttpError(404, "Khong tim thay lan chay de so sanh")
    return result


@route("POST", r"/api/manual-marks")
def api_manual_mark(req, _m):
    body = req.json_body()
    ip = body.get("ip")
    check_id = body.get("check_id")
    status = body.get("status") or ""
    if not ip or check_id not in store.checks_by_id():
        raise HttpError(400, "Thieu ip hoac check_id khong hop le")
    if status and status not in ("PASS", "FAIL", "NA", "MANUAL"):
        raise HttpError(400, "status khong hop le")
    store.set_mark(ip, check_id, status, body.get("note"))
    return {"ok": True}


# ==================================================================== HTTP


class App(BaseHTTPRequestHandler):
    server_version = "HardeningScanner"
    protocol_version = "HTTP/1.1"

    # -------------------------------------------------- tien ich

    def json_body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise HttpError(400, "Body khong phai JSON hop le") from exc

    def _send(self, status: int, body: bytes, content_type: str,
              extra: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def send_json(self, obj: Any, status: int = 200) -> None:
        self._send(status, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    def log_message(self, fmt: str, *args: Any) -> None:
        if self.path.startswith("/api/scans/") and self.path.endswith("/stream"):
            return
        print(f"  {self.command} {self.path} -> {args[1] if len(args) > 1 else ''}")

    # -------------------------------------------------- dinh tuyen

    def dispatch(self, method: str) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        self.query = urllib.parse.parse_qs(parsed.query)

        # SSE va tai file xu ly rieng vi khong tra JSON
        if method == "GET":
            m = re.match(r"^/api/scans/(\d+)/stream$", path)
            if m:
                return self.serve_stream(int(m.group(1)))
            m = re.match(r"^/api/scans/(\d+)/report\.(csv|html)$", path)
            if m:
                return self.serve_report(int(m.group(1)), m.group(2))

        for route_method, pattern, fn in ROUTES:
            if route_method != method:
                continue
            m = pattern.match(path)
            if m:
                try:
                    return self.send_json(fn(self, m))
                except HttpError as exc:
                    return self.send_json({"detail": exc.message}, exc.status)
                except Exception as exc:  # noqa: BLE001
                    import traceback
                    traceback.print_exc()
                    return self.send_json({"detail": f"Loi may chu: {exc}"}, 500)

        if method == "GET":
            return self.serve_static(path)
        self.send_json({"detail": "Khong tim thay endpoint"}, 404)

    def do_GET(self) -> None:
        self.dispatch("GET")

    def do_POST(self) -> None:
        self.dispatch("POST")

    def do_PUT(self) -> None:
        self.dispatch("PUT")

    def do_DELETE(self) -> None:
        self.dispatch("DELETE")

    # -------------------------------------------------- file tinh

    def serve_static(self, path: str) -> None:
        rel = path.lstrip("/") or "index.html"
        target = (store.WEB_DIR / rel).resolve()
        try:
            target.relative_to(store.WEB_DIR.resolve())
        except ValueError:
            return self.send_json({"detail": "Duong dan khong hop le"}, 403)
        if not target.is_file():
            return self.send_json({"detail": "Khong tim thay"}, 404)

        ctype = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript", "application/json"):
            ctype += "; charset=utf-8"
        self._send(200, target.read_bytes(), ctype, {"Cache-Control": "no-cache"})

    # -------------------------------------------------- report tai ve

    def serve_report(self, run_id: int, fmt: str) -> None:
        if store.get_run_meta(run_id) is None:
            return self.send_json({"detail": "Khong tim thay lan chay"}, 404)
        if fmt == "csv":
            self._send(200, reports.report_csv(run_id), "text/csv; charset=utf-8",
                       {"Content-Disposition": f'attachment; filename="hardening-{run_id}.csv"'})
        else:
            self._send(200, reports.report_html(run_id), "text/html; charset=utf-8")

    # -------------------------------------------------- log realtime (SSE)

    def serve_stream(self, run_id: int) -> None:
        job = jobs.get_job(run_id)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True

        def write(chunk: str) -> bool:
            try:
                self.wfile.write(chunk.encode("utf-8"))
                self.wfile.flush()
                return True
            except (BrokenPipeError, ConnectionResetError, OSError):
                return False

        if job is None:
            for line in store.read_log(run_id):
                if not write("data: " + json.dumps({"line": line}) + "\n\n"):
                    return
            write("event: end\ndata: {}\n\n")
            return

        sent = 0
        idle = 0.0
        while True:
            total = len(job.lines)
            if sent < total:
                for line in job.lines[sent:total]:
                    if not write("data: " + json.dumps({"line": line}) + "\n\n"):
                        return
                    if line.startswith("__JOB_END__"):
                        write("event: end\ndata: {}\n\n")
                        return
                sent = total
                idle = 0.0
            else:
                if job.finished:
                    write("event: end\ndata: {}\n\n")
                    return
                time.sleep(0.25)
                idle += 0.25
                if idle >= 15:
                    idle = 0.0
                    if not write(": keepalive\n\n"):
                        return


def serve(host: str = "127.0.0.1", port: int = 8000) -> None:
    store.ensure_dirs()
    httpd = ThreadingHTTPServer((host, port), App)
    httpd.daemon_threads = True
    banner = [
        f"  VDI Hardening Scanner dang chay tai  http://{host}:{port}",
        f"  Du lieu luu tai                      {store.DATA_DIR}",
    ]
    if not jobs.ansible_available():
        banner += ["  CANH BAO: khong tim thay ansible-playbook trong PATH.",
                   "            Cai bang: pip install ansible-core"]
    if not jobs.sshpass_available():
        banner.append("  Luu y: khong co sshpass - chi dung duoc xac thuc bang SSH key.")
    banner.append("  Nhan Ctrl+C de dung.\n")
    print("\n".join(banner), flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  Da dung.")
    finally:
        httpd.server_close()
