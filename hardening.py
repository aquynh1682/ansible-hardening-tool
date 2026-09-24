#!/usr/bin/env python3
# VDI Hardening Scanner
# Tac gia: Quynh Ngo. Ho tro: Claude (Anthropic) qua Claude Code.
# Cap nhat: 2026-09-24. Lich su day du: git log -- <duong dan file>

"""VDI Hardening Scanner - diem khoi dong.

    python3 hardening.py                  # http://127.0.0.1:8000
    python3 hardening.py --port 9000
    python3 hardening.py --host 0.0.0.0   # cho may khac truy cap (can than!)

Chi dung thu vien chuan cua Python. Phu thuoc duy nhat ben ngoai la
ansible-playbook, va chi can khi thuc su quet / trien khai.
"""
from __future__ import annotations

import argparse
import sys
import webbrowser

MIN_PYTHON = (3, 9)


def main() -> int:
    if sys.version_info < MIN_PYTHON:
        print(f"Can Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]} tro len, "
              f"dang chay {sys.version.split()[0]}")
        return 1

    parser = argparse.ArgumentParser(description="VDI Hardening Scanner")
    parser.add_argument("--host", default="127.0.0.1",
                        help="dia chi lang nghe (mac dinh 127.0.0.1 - chi may nay)")
    parser.add_argument("--port", type=int, default=8000, help="cong (mac dinh 8000)")
    parser.add_argument("--open", action="store_true", help="tu mo trinh duyet")
    args = parser.parse_args()

    from app import server

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print("  CANH BAO: dang mo ra ngoai localhost. Cong cu khong co xac thuc")
        print("            nguoi dung - chi lam vay trong mang quan tri tin cay.\n")

    if args.open:
        url = f"http://{'127.0.0.1' if args.host == '0.0.0.0' else args.host}:{args.port}"
        webbrowser.open(url)

    server.serve(args.host, args.port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
