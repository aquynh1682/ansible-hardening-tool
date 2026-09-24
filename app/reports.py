# VDI Hardening Scanner
# Tac gia: Quynh Ngo. Ho tro: Claude (Anthropic) qua Claude Code.
# Cap nhat: 2026-09-24. Lich su day du: git log -- <duong dan file>

"""Ghep ket qua quet voi catalog va xuat report."""
from __future__ import annotations

import csv
import html
import io
from typing import Any

from . import store

STATUS_COLOR = {
    "PASS": "#0f7b3f", "FAIL": "#b3261e", "WARN": "#8a5300",
    "MANUAL": "#4a5568", "NA": "#6b7280", "ERROR": "#7c2d12",
}


def scan_detail(run_id: int) -> dict[str, Any] | None:
    meta = store.get_run_meta(run_id)
    if meta is None:
        return None

    meta_info = store.checks_by_id()
    marks = store.get_marks()
    hosts_out = []

    for host in store.get_results(run_id):
        enriched = []
        for r in host.get("results", []):
            info = meta_info.get(r.get("id"), {})
            mark = marks.get(f"{host['ip']}|{r.get('id')}")
            enriched.append({
                "check_id": r.get("id"),
                "status": r.get("status"),
                "actual": r.get("actual"),
                "evidence": r.get("evidence"),
                "title": info.get("title", r.get("id")),
                "section": info.get("section"),
                "severity": info.get("severity", "medium"),
                "expected": info.get("expected"),
                "purpose": info.get("purpose"),
                "no": info.get("no"),
                "remediable": bool(info.get("remediable")),
                "mode": info.get("mode", "auto"),
                "note": info.get("note"),
                "manual_status": mark["status"] if mark else None,
                "manual_note": mark["note"] if mark else None,
                "effective_status": mark["status"] if mark else r.get("status"),
            })

        summary: dict[str, int] = {}
        for r in enriched:
            summary[r["effective_status"]] = summary.get(r["effective_status"], 0) + 1

        hosts_out.append({
            "ip": host["ip"],
            "ok": host.get("ok", False),
            "error": host.get("error"),
            "facts": host.get("facts", {}),
            "summary": summary,
            "results": enriched,
        })

    totals: dict[str, int] = {}
    for h in hosts_out:
        for k, v in h["summary"].items():
            totals[k] = totals.get(k, 0) + v

    return {"scan": meta, "hosts": hosts_out, "totals": totals}


def report_rows(run_id: int) -> list[dict[str, Any]]:
    detail = scan_detail(run_id)
    if not detail:
        return []
    rows = []
    for host in detail["hosts"]:
        for r in host["results"]:
            rows.append({
                "host": host["ip"],
                "os": host["facts"].get("os_name", ""),
                "stt": r.get("no", ""),
                "check_id": r["check_id"],
                "title": r["title"],
                "purpose": r.get("purpose") or "",
                "expected": r.get("expected") or "",
                "status": r["effective_status"],
                "severity": r["severity"],
                "actual": r.get("actual") or "",
                "manual_note": r.get("manual_note") or "",
            })
    return rows


def report_csv(run_id: int) -> bytes:
    rows = report_rows(run_id)
    buf = io.StringIO()
    buf.write("﻿")  # BOM de Excel doc dung tieng Viet
    fields = ["host", "os", "stt", "check_id", "title", "purpose",
              "expected", "status", "severity", "actual", "manual_note"]
    writer = csv.DictWriter(buf, fieldnames=fields)
    writer.writeheader()
    writer.writerows(rows)
    return buf.getvalue().encode("utf-8")


def report_html(run_id: int) -> bytes:
    detail = scan_detail(run_id)
    if not detail:
        return b"<h1>Khong tim thay lan quet</h1>"
    scan = detail["scan"]
    e = html.escape

    parts = [
        "<!doctype html><html lang='vi'><head><meta charset='utf-8'>",
        f"<title>Bao cao hardening #{run_id}</title><style>",
        "body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:24px;color:#111;background:#fff}",
        "h1{font-size:20px}h2{font-size:16px;margin-top:28px}",
        "table{border-collapse:collapse;width:100%;font-size:12px;margin-top:8px}",
        "th,td{border:1px solid #d0d5dd;padding:6px 8px;vertical-align:top;text-align:left}",
        "th{background:#f2f4f7}.st{font-weight:700;white-space:nowrap}.meta{color:#555;font-size:13px}",
        "@media print{h2{page-break-before:auto}tr{page-break-inside:avoid}}",
        "</style></head><body>",
        f"<h1>Bao cao danh gia hardening &mdash; lan chay #{run_id}</h1>",
        f"<p class='meta'>Loai: {e(str(scan.get('kind')))} &middot; Trang thai: {e(str(scan.get('status')))}"
        f" &middot; Bat dau: {e(str(scan.get('started_at')))}"
        f" &middot; Ket thuc: {e(str(scan.get('finished_at')))}</p>",
        "<p class='meta'>Tong hop: "
        + " &middot; ".join(f"{k}: {v}" for k, v in sorted(detail["totals"].items())) + "</p>",
    ]

    for host in detail["hosts"]:
        f = host["facts"]
        parts.append(f"<h2>{e(host['ip'])} &mdash; {e(str(f.get('os_name', 'khong ro')))}</h2>")
        parts.append(
            "<p class='meta'>Hostname: %s &middot; RAM: %s GB &middot; CPU: %s &middot; Ao hoa: %s</p>"
            % (e(str(f.get("hostname", "-"))), e(str(f.get("ram_gb", "-"))),
               e(str(f.get("cpu_count", "-"))), e(str(f.get("virtualization", "-"))))
        )
        parts.append("<table><tr><th>ID</th><th>Tieu chi</th><th>Yeu cau muc dat</th>"
                     "<th>Ket qua</th><th>Thuc te ghi nhan</th></tr>")
        for r in host["results"]:
            extra = " | Ghi chu: " + r["manual_note"] if r.get("manual_note") else ""
            parts.append(
                "<tr><td>%s</td><td>%s</td><td>%s</td><td class='st' style='color:%s'>%s</td><td>%s</td></tr>"
                % (e(r["check_id"]), e(r["title"]), e(r.get("expected") or ""),
                   STATUS_COLOR.get(r["effective_status"], "#333"),
                   e(r["effective_status"]), e((r.get("actual") or "") + extra))
            )
        parts.append("</table>")

    parts.append("</body></html>")
    return "".join(parts).encode("utf-8")


def compare(before: int, after: int) -> dict[str, Any] | None:
    a = scan_detail(before)
    b = scan_detail(after)
    if a is None or b is None:
        return None

    def index(detail: dict[str, Any]) -> dict[tuple[str, str], str]:
        return {(h["ip"], r["check_id"]): r["effective_status"]
                for h in detail["hosts"] for r in h["results"]}

    ia, ib = index(a), index(b)
    meta = store.checks_by_id()
    changes = []
    for key in sorted(set(ia) | set(ib)):
        old, new = ia.get(key), ib.get(key)
        if old == new:
            continue
        changes.append({
            "host": key[0], "check_id": key[1],
            "title": meta.get(key[1], {}).get("title", key[1]),
            "before": old, "after": new,
            "improved": old in ("FAIL", "WARN", "ERROR") and new == "PASS",
            "regressed": old == "PASS" and new in ("FAIL", "WARN", "ERROR"),
        })

    return {
        "before": {"id": before, "totals": a["totals"]},
        "after": {"id": after, "totals": b["totals"]},
        "changes": changes,
        "fixed": sum(1 for c in changes if c["improved"]),
        "regressed": sum(1 for c in changes if c["regressed"]),
    }
