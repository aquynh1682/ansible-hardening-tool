#!/usr/bin/env python3
# VDI Hardening Scanner
# Tac gia: Quynh Ngo. Ho tro: Claude (Anthropic) qua Claude Code.
# Cap nhat: 2026-09-24. Lich su day du: git log -- <duong dan file>

"""Kiem tra tinh nhat quan giua catalog / audit agent / tag Ansible.

Chay moi khi them hoac sua mot muc checklist:

    python3 tests/check_consistency.py
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REQUIRED_FIELDS = ("id", "section", "title", "purpose", "expected", "mode", "remediable", "severity")

failures: list[str] = []


def check(label: str, cond: bool, detail: str = "") -> None:
    print(("  OK   " if cond else "  FAIL ") + label + ("" if cond else " -> " + detail))
    if not cond:
        failures.append(label)


def main() -> int:
    catalog = json.loads((ROOT / "catalog/checklist.json").read_text(encoding="utf-8"))
    checks = catalog["checks"]
    ids = [c["id"] for c in checks]
    remediable = {c["id"] for c in checks if c.get("remediable")}
    sections = {s["id"] for s in catalog["sections"]}

    agent_src = (ROOT / "ansible/files/audit_agent.py").read_text(encoding="utf-8")
    agent_ids = set(re.findall(r'^\s*\("((?:OS|VIRT)-\d+)",\s*\w+\),', agent_src, re.M))

    tags: set[str] = set()
    for path in (ROOT / "ansible/roles/harden/tasks").glob("*.yml"):
        tags |= set(re.findall(r'tags:\s*\["((?:OS|VIRT)-\d+)"\]', path.read_text(encoding="utf-8")))

    print(f"Catalog: {len(ids)} muc | Agent: {len(agent_ids)} | Tag Ansible: {len(tags)} | remediable: {len(remediable)}")

    check("ID catalog khong trung lap", len(ids) == len(set(ids)),
          str(sorted({i for i in ids if ids.count(i) > 1})))
    check("Audit agent phu kin catalog", agent_ids == set(ids),
          f"thieu trong agent={sorted(set(ids) - agent_ids)} thua={sorted(agent_ids - set(ids))}")
    check("Moi muc remediable deu co tag Ansible tuong ung", remediable == tags,
          f"thieu tag={sorted(remediable - tags)} tag thua={sorted(tags - remediable)}")
    check("Muc manual khong duoc danh dau remediable",
          not [c["id"] for c in checks if c.get("mode") == "manual" and c.get("remediable")],
          str([c["id"] for c in checks if c.get("mode") == "manual" and c.get("remediable")]))
    check("Moi check co du truong bat buoc",
          all(all(k in c for k in REQUIRED_FIELDS) for c in checks),
          str([c.get("id") for c in checks if not all(k in c for k in REQUIRED_FIELDS)]))
    check("Section cua moi check deu duoc khai bao",
          all(c["section"] in sections for c in checks),
          str(sorted({c["section"] for c in checks} - sections)))

    if failures:
        print(f"\n{len(failures)} kiem tra that bai.")
        return 1
    print("\nTat ca kiem tra deu dat.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
