#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# VDI Hardening Scanner
# Tac gia: Quynh Ngo. Ho tro: Claude (Anthropic) qua Claude Code.
# Cap nhat: 2026-09-24. Lich su day du: git log -- <duong dan file>

"""
Hardening audit agent - READ ONLY.

Chay tren host dich (qua Ansible), khong sua doi bat ky thu gi tren he thong.
Nhan config JSON (base64) o argv[1], in ket qua JSON ra stdout.

Tuong thich Python 3.6+ (Ubuntu 18.04 tro len).
"""

import base64
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import time

PASS = "PASS"
FAIL = "FAIL"
WARN = "WARN"
MANUAL = "MANUAL"
NA = "NA"
ERROR = "ERROR"

DEFAULT_CONFIG = {
    "timezone": "Asia/Ho_Chi_Minh",
    "ntp_servers": [],
    "ntp_min_servers": 2,
    "nofile_min": 65535,
    "nproc_min": 8192,
    "conntrack_max_min": 524288,
    "conntrack_hashsize": 131072,
    "tmout": 300,
    "ssh_max_auth_tries": 3,
    "ssh_client_alive_interval": 300,
    "ssh_client_alive_count_max": 3,
    "openssl_min_version": "1.1.1",
    "log_servers": [],
    "internal_repo_hosts": [],
    "admin_networks": [],
    "business_users": [],
    "unowned_scan": True,
    "unowned_scan_timeout": 120,
    "sysctl_guideline": {
        "net.ipv4.conf.all.rp_filter": "1",
        "net.ipv4.conf.default.rp_filter": "1",
        "net.ipv4.conf.all.accept_redirects": "0",
        "net.ipv4.conf.default.accept_redirects": "0",
        "net.ipv6.conf.all.accept_redirects": "0",
        "net.ipv6.conf.default.accept_redirects": "0",
        "net.ipv4.conf.all.send_redirects": "0",
        "net.ipv4.conf.default.send_redirects": "0",
        "net.ipv4.icmp_echo_ignore_broadcasts": "1",
        "net.ipv4.tcp_syncookies": "1",
        "net.ipv4.conf.all.accept_source_route": "0",
        "net.ipv4.conf.default.accept_source_route": "0",
        "net.ipv4.conf.all.log_martians": "1",
        "net.ipv4.conf.default.log_martians": "1",
        "fs.suid_dumpable": "0",
        "kernel.randomize_va_space": "2",
        "vm.zone_reclaim_mode": "0",
        "vm.swappiness": "10",
        "net.core.somaxconn": "65535",
        "net.ipv4.tcp_max_syn_backlog": "8192",
    },
}

STRONG_MACS = set(
    [
        "hmac-sha2-512-etm@openssh.com",
        "hmac-sha2-256-etm@openssh.com",
        "umac-128-etm@openssh.com",
        "hmac-sha2-512",
        "hmac-sha2-256",
    ]
)

# Tien trinh he thong duoc phep chay duoi root (OS-08)
ROOT_PROC_ALLOWLIST = set(
    [
        "systemd", "systemd-journal", "systemd-journald", "systemd-udevd", "systemd-logind",
        "systemd-network", "systemd-networkd", "systemd-resolve", "systemd-resolved",
        "systemd-timesyn", "systemd-timesyncd", "systemd-udevadm", "systemd-machine",
        "init", "kthreadd", "khelper", "kdevtmpfs", "kworker",
        "sshd", "cron", "crond", "atd", "rsyslogd", "syslog-ng", "chronyd", "chronyc",
        "ntpd", "agetty", "login", "dbus-daemon", "dbus-broker", "polkitd", "irqbalance",
        "acpid", "auditd", "audispd", "snapd", "unattended-upgr", "networkd-dispat",
        "multipathd", "lvmetad", "iscsid", "kdumpctl", "lldpd", "udisksd", "accounts-daemon",
        "ModemManager", "packagekitd", "cloud-init", "amazon-ssm-agen", "qemu-ga",
        "VGAuthService", "vmtoolsd", "open-vm-tools", "sudo", "su", "bash", "sh", "dash",
        "python3", "python", "ps", "audit_agent.py", "tail", "sleep", "ansible",
        "gmain", "gdbus", "pool", "dhclient", "wpa_supplicant", "rpcbind", "rpc.statd",
        "master",  # postfix master - se bi bat boi OS-15 neu dang chay
    ]
)


def run(cmd, timeout=60):
    """Chay lenh shell, tra ve (rc, stdout, stderr). Khong bao gio raise."""
    try:
        p = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
        out, err = p.communicate(timeout=timeout)
        return p.returncode, (out or "").strip(), (err or "").strip()
    except subprocess.TimeoutExpired:
        try:
            p.kill()
        except Exception:
            pass
        return 124, "", "timeout after %ss" % timeout
    except Exception as exc:  # noqa: BLE001
        return 127, "", str(exc)


def read_file(path, limit=200000):
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read(limit)
    except Exception:
        return None


def read_lines(path):
    content = read_file(path)
    if content is None:
        return []
    return content.splitlines()


def has_cmd(name):
    return shutil.which(name) is not None


def unit_state(unit):
    """Tra ve (active, enabled) dang chuoi; 'not-installed' neu unit khong ton tai."""
    rc, out, _ = run("systemctl is-active %s 2>/dev/null" % unit, timeout=15)
    active = out or "unknown"
    rc2, out2, _ = run("systemctl is-enabled %s 2>/dev/null" % unit, timeout=15)
    enabled = out2 or "unknown"
    if active in ("unknown", "") and enabled in ("unknown", ""):
        rc3, out3, _ = run("systemctl list-unit-files %s 2>/dev/null | wc -l" % unit, timeout=15)
        if out3.strip() in ("0", "1", "2"):
            return "not-installed", "not-installed"
    return active, enabled


def sysctl_get(key):
    path = "/proc/sys/" + key.replace(".", "/")
    val = read_file(path)
    if val is not None:
        return " ".join(val.split())
    rc, out, _ = run("sysctl -n %s 2>/dev/null" % key, timeout=10)
    if rc == 0 and out:
        return " ".join(out.split())
    return None


def truncate(text, limit=4000):
    if text is None:
        return ""
    text = str(text)
    if len(text) <= limit:
        return text
    return text[:limit] + "\n... (da cat bot %d ky tu)" % (len(text) - limit)


def version_tuple(v):
    parts = re.findall(r"\d+", v or "")
    return tuple(int(x) for x in parts[:4]) or (0,)


# ---------------------------------------------------------------- facts


def collect_facts():
    facts = {}
    osr = {}
    for line in read_lines("/etc/os-release"):
        if "=" in line:
            k, _, v = line.partition("=")
            osr[k.strip()] = v.strip().strip('"')
    facts["os_name"] = osr.get("PRETTY_NAME") or osr.get("NAME") or "unknown"
    facts["os_id"] = osr.get("ID", "unknown")
    facts["os_version_id"] = osr.get("VERSION_ID", "")
    facts["os_family"] = "debian" if osr.get("ID_LIKE", osr.get("ID", "")).find("debian") >= 0 or osr.get("ID") == "debian" else (
        "rhel" if osr.get("ID") in ("rhel", "centos", "rocky", "almalinux", "fedora") or "rhel" in osr.get("ID_LIKE", "") else "other"
    )

    rc, out, _ = run("uname -r", timeout=10)
    facts["kernel"] = out
    rc, out, _ = run("hostname -f 2>/dev/null || hostname", timeout=10)
    facts["hostname"] = out

    mem_kb = 0
    for line in read_lines("/proc/meminfo"):
        if line.startswith("MemTotal:"):
            try:
                mem_kb = int(line.split()[1])
            except Exception:
                mem_kb = 0
            break
    facts["mem_total_kb"] = mem_kb
    facts["ram_gb"] = max(1, int(round(mem_kb / 1048576.0))) if mem_kb else 0

    rc, out, _ = run("nproc 2>/dev/null", timeout=10)
    try:
        facts["cpu_count"] = int(out)
    except Exception:
        facts["cpu_count"] = 0

    rc, out, _ = run("systemd-detect-virt 2>/dev/null", timeout=10)
    virt = out if rc == 0 and out else "none"
    facts["virtualization"] = virt
    facts["is_virtual"] = virt not in ("none", "", "unknown")

    rc, out, _ = run("uptime -p 2>/dev/null", timeout=10)
    facts["uptime"] = out
    facts["agent_time"] = time.strftime("%Y-%m-%d %H:%M:%S %z")
    return facts


# ---------------------------------------------------------------- helpers dung chung


def parse_sshd_config():
    """Tra ve dict cau hinh sshd hieu luc (tu sshd -T)."""
    rc, out, err = run("sshd -T 2>/dev/null", timeout=30)
    if rc != 0 or not out:
        rc, out, err = run("/usr/sbin/sshd -T 2>/dev/null", timeout=30)
    cfg = {}
    for line in (out or "").splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            key = parts[0].lower()
            if key in cfg:
                cfg[key] = cfg[key] + "," + parts[1]
            else:
                cfg[key] = parts[1]
        elif len(parts) == 1 and parts[0]:
            cfg.setdefault(parts[0].lower(), "")
    return cfg, (err or "")


def get_login_users():
    """User co shell dang nhap duoc, kem uid va shell."""
    users = []
    for line in read_lines("/etc/passwd"):
        parts = line.split(":")
        if len(parts) < 7:
            continue
        name, _, uid, gid, _, home, shell = parts[:7]
        try:
            uid_i = int(uid)
        except ValueError:
            continue
        if shell.split("/")[-1] in ("nologin", "false", "sync", "shutdown", "halt"):
            continue
        users.append({"name": name, "uid": uid_i, "shell": shell, "home": home})
    return users


def shadow_map():
    """Tra ve dict user -> fields cua /etc/shadow (chi doc duoc khi la root)."""
    data = {}
    for line in read_lines("/etc/shadow"):
        parts = line.split(":")
        if len(parts) >= 8:
            data[parts[0]] = parts
    return data


def sudoers_effective_lines():
    """Cac dong rule co hieu luc trong sudoers + sudoers.d (bo comment/rong)."""
    files = ["/etc/sudoers"] + sorted(glob.glob("/etc/sudoers.d/*"))
    lines = []
    for path in files:
        if os.path.isdir(path):
            continue
        for raw in read_lines(path):
            s = raw.strip()
            if not s or s.startswith("#") or s.startswith("@includedir") or s.startswith("#includedir"):
                continue
            lines.append({"file": path, "line": s})
    return lines


def limits_effective():
    """Gom cac entry limits: (domain, type, item) -> value (lay dong cuoi cung)."""
    entries = {}
    files = ["/etc/security/limits.conf"] + sorted(glob.glob("/etc/security/limits.d/*.conf"))
    for path in files:
        for raw in read_lines(path):
            s = raw.strip()
            if not s or s.startswith("#"):
                continue
            parts = s.split()
            if len(parts) < 4:
                continue
            domain, ltype, item, value = parts[0], parts[1].lower(), parts[2].lower(), parts[3]
            entries[(domain, ltype, item)] = {"value": value, "file": path}
    return entries


def limits_check(entries, item, minimum, domains):
    """Kiem tra soft/hard cua 'item' >= minimum cho tung domain. Tra ve (ok, details)."""
    details = []
    ok = True
    for domain in domains:
        for ltype in ("soft", "hard"):
            rec = entries.get((domain, ltype, item))
            if rec is None:
                ok = False
                details.append("%s %s %s = (chua cau hinh)" % (domain, ltype, item))
                continue
            val = rec["value"]
            if val in ("unlimited", "infinity"):
                details.append("%s %s %s = %s (OK)" % (domain, ltype, item, val))
                continue
            try:
                num = int(val)
            except ValueError:
                ok = False
                details.append("%s %s %s = %s (khong hop le)" % (domain, ltype, item, val))
                continue
            if num < minimum:
                ok = False
                details.append("%s %s %s = %d (< %d)" % (domain, ltype, item, num, minimum))
            else:
                details.append("%s %s %s = %d (OK)" % (domain, ltype, item, num))
    return ok, details


# ---------------------------------------------------------------- cac check


def check_os01_mount(cfg, facts):
    mounts = []
    for line in read_lines("/proc/mounts"):
        parts = line.split()
        if len(parts) >= 3:
            mounts.append({"dev": parts[0], "mp": parts[1], "fs": parts[2]})
    real_fs = ("ext2", "ext3", "ext4", "xfs", "btrfs", "jfs", "reiserfs", "zfs", "nfs", "nfs4")
    real = [m for m in mounts if m["fs"] in real_fs]
    mps = set(m["mp"] for m in real)

    var_sep = "/var" in mps
    data_mps = sorted(mp for mp in mps if mp not in ("/", "/boot", "/boot/efi", "/var"))

    rc, df_out, _ = run("df -hT -x tmpfs -x devtmpfs -x squashfs 2>/dev/null", timeout=20)

    problems = []
    if not var_sep:
        problems.append("/var chua duoc tach khoi phan vung /")
    if not data_mps:
        problems.append("Khong thay phan vung rieng cho ung dung/DB")

    status = PASS if not problems else FAIL
    actual = "/var tach rieng: %s | Phan vung du lieu rieng: %s" % (
        "co" if var_sep else "khong",
        ", ".join(data_mps) if data_mps else "khong co",
    )
    if problems and facts.get("is_virtual"):
        actual += " | Luu y: may ao/cloud co the duoc mien theo ghi chu checklist"
    return status, actual, df_out


def check_os02_timezone(cfg, facts):
    rc, out, _ = run("timedatectl show -p Timezone -p LocalRTC --value 2>/dev/null", timeout=15)
    tz = ""
    local_rtc = ""
    if rc == 0 and out:
        vals = out.splitlines()
        tz = vals[0].strip() if len(vals) > 0 else ""
        local_rtc = vals[1].strip() if len(vals) > 1 else ""
    if not tz:
        link = None
        try:
            link = os.path.realpath("/etc/localtime")
        except Exception:
            link = None
        if link and "/zoneinfo/" in link:
            tz = link.split("/zoneinfo/", 1)[1]
    rc, dateout, _ = run('date +"%Z %z"', timeout=10)

    want_tz = cfg["timezone"]
    ok_tz = tz == want_tz
    ok_offset = dateout.endswith("+0700")
    ok_rtc = local_rtc.lower() in ("no", "false", "")

    status = PASS if (ok_tz and ok_offset and ok_rtc) else FAIL
    actual = "Timezone=%s | date=%s | LocalRTC=%s" % (tz or "?", dateout or "?", local_rtc or "?")
    evidence = "Mong doi: Timezone=%s, offset +0700, LocalRTC=no" % want_tz
    return status, actual, evidence


def check_os03_ntp(cfg, facts):
    active, enabled = unit_state("chrony")
    if active == "not-installed":
        active, enabled = unit_state("chronyd")
    svc = "chrony/chronyd"
    if active == "not-installed":
        a2, e2 = unit_state("systemd-timesyncd")
        if a2 != "not-installed":
            active, enabled, svc = a2, e2, "systemd-timesyncd"

    sources = []
    conf_servers = []
    for path in ["/etc/chrony/chrony.conf", "/etc/chrony.conf"] + sorted(
        glob.glob("/etc/chrony/conf.d/*.conf") + glob.glob("/etc/chrony/sources.d/*.sources")
    ):
        for line in read_lines(path):
            s = line.strip()
            if s.startswith("server ") or s.startswith("pool ") or s.startswith("peer "):
                conf_servers.append(s.split()[1])

    rc, src_out, _ = run("chronyc -n sources 2>/dev/null", timeout=20)
    rc2, track_out, _ = run("chronyc tracking 2>/dev/null", timeout=20)
    synced = "Leap status" in track_out and "Normal" in track_out

    n = len(set(conf_servers))
    problems = []
    if active != "active":
        problems.append("service %s khong active (%s)" % (svc, active))
    if svc != "systemd-timesyncd" and n < cfg["ntp_min_servers"]:
        problems.append("chi co %d NTP server trong cau hinh (yeu cau >= %d)" % (n, cfg["ntp_min_servers"]))
    if svc == "systemd-timesyncd":
        problems.append("dang dung systemd-timesyncd thay vi chrony")
    if not synced and svc != "systemd-timesyncd":
        problems.append("chua dong bo (Leap status khac Normal)")

    status = PASS if not problems else FAIL
    actual = "service=%s active=%s enabled=%s | servers=%s" % (
        svc, active, enabled, ", ".join(sorted(set(conf_servers))) or "khong co"
    )
    if problems:
        actual += " | Van de: " + "; ".join(problems)
    return status, actual, truncate((src_out or "") + "\n" + (track_out or ""))


def check_os04_crontab(cfg, facts):
    rc, root_cron, _ = run("crontab -l -u root 2>/dev/null", timeout=20)
    root_entries = [
        l.strip()
        for l in (root_cron or "").splitlines()
        if l.strip() and not l.strip().startswith("#")
    ]

    cron_d = []
    for path in sorted(glob.glob("/etc/cron.d/*")):
        base = os.path.basename(path)
        if base in (".placeholder", "e2scrub_all", "anacron"):
            continue
        for line in read_lines(path):
            s = line.strip()
            if s and not s.startswith("#") and "=" not in s.split()[0]:
                cron_d.append("%s: %s" % (base, s))

    other_users = []
    for path in sorted(glob.glob("/var/spool/cron/crontabs/*") + glob.glob("/var/spool/cron/*")):
        if os.path.isfile(path) and os.path.basename(path) != "root":
            other_users.append(os.path.basename(path))

    total = len(root_entries) + len(cron_d)
    if total == 0 and not other_users:
        status = PASS
        actual = "Khong co crontab nao cua root (no crontab for root) va khong co job trong /etc/cron.d"
    else:
        status = WARN
        actual = "Co %d job crontab root, %d job trong /etc/cron.d, crontab user khac: %s. Can review va xac nhan tung job." % (
            len(root_entries), len(cron_d), ", ".join(other_users) or "khong co"
        )
    evidence = "crontab -l -u root:\n" + (root_cron or "(trong)") + "\n\n/etc/cron.d:\n" + (
        "\n".join(cron_d) or "(trong)"
    )
    return status, actual, truncate(evidence)


def check_os05_users(cfg, facts):
    users = get_login_users()
    shadow = shadow_map()
    normal = [u for u in users if u["uid"] >= 1000 and u["name"] != "nobody"]
    system_login = [u for u in users if u["uid"] < 1000 and u["name"] != "root"]

    empty_pw = []
    locked_note = []
    for u in users:
        rec = shadow.get(u["name"])
        if rec is None:
            continue
        pw = rec[1]
        if pw == "":
            empty_pw.append(u["name"])
        elif pw in ("*", "!", "!!") or pw.startswith("!"):
            locked_note.append(u["name"])

    cron_allow = os.path.exists("/etc/cron.allow")
    sshd, _ = parse_sshd_config()
    allow_users = sshd.get("allowusers", "")
    allow_groups = sshd.get("allowgroups", "")
    has_ssh_allowlist = bool(allow_users or allow_groups)

    problems = []
    if empty_pw:
        problems.append("tai khoan KHONG CO MAT KHAU: %s" % ", ".join(empty_pw))
    if not cron_allow:
        problems.append("chua co /etc/cron.allow de gioi han crontab")
    if not has_ssh_allowlist:
        problems.append("sshd chua co AllowUsers/AllowGroups de gioi han SSH")

    status = FAIL if problems else PASS
    actual = "User thuong (uid>=1000): %s | User he thong co shell: %s | cron.allow: %s | SSH allowlist: %s" % (
        ", ".join("%s(%d)" % (u["name"], u["uid"]) for u in normal) or "khong co",
        ", ".join(u["name"] for u in system_login) or "khong co",
        "co" if cron_allow else "khong",
        (allow_users + " " + allow_groups).strip() or "khong co",
    )
    if problems:
        actual += " | Van de: " + "; ".join(problems)
    evidence = "Tai khoan bi khoa (khong dang nhap bang mat khau): %s" % (", ".join(locked_note) or "khong co")
    return status, actual, evidence


def check_os06_sudo(cfg, facts):
    rules = sudoers_effective_lines()
    nopasswd_all = []
    nopasswd_limited = []
    for r in rules:
        line = r["line"]
        if "NOPASSWD" not in line.upper():
            continue
        after = line.upper().split("NOPASSWD:", 1)[1].strip() if "NOPASSWD:" in line.upper() else ""
        if after.startswith("ALL"):
            nopasswd_all.append("%s: %s" % (r["file"], line))
        else:
            nopasswd_limited.append("%s: %s" % (r["file"], line))

    status = FAIL if nopasswd_all else PASS
    actual = "Rule NOPASSWD:ALL: %d | Rule NOPASSWD gioi han lenh: %d" % (
        len(nopasswd_all), len(nopasswd_limited)
    )
    if nopasswd_all:
        actual += " | VI PHAM: " + " || ".join(nopasswd_all)
    evidence = "Toan bo rule sudoers hieu luc:\n" + "\n".join("%s: %s" % (r["file"], r["line"]) for r in rules)
    return status, actual, truncate(evidence)


def check_os07_uid0(cfg, facts):
    uid0 = []
    for line in read_lines("/etc/passwd"):
        parts = line.split(":")
        if len(parts) >= 3 and parts[2] == "0":
            uid0.append(parts[0])
    extra = [u for u in uid0 if u != "root"]
    status = PASS if not extra else FAIL
    actual = "User co UID=0: %s" % ", ".join(uid0)
    if extra:
        actual += " | VI PHAM: ngoai root con co %s" % ", ".join(extra)
    return status, actual, ""


def check_os08_root_apps(cfg, facts):
    rc, out, _ = run("ps -eo user:32,pid,ppid,comm,args --no-headers 2>/dev/null", timeout=30)
    suspects = []
    for line in (out or "").splitlines():
        parts = line.split(None, 4)
        if len(parts) < 5:
            continue
        user, pid, ppid, comm, args = parts
        if user != "root":
            continue
        if args.startswith("["):  # kernel thread
            continue
        if comm in ROOT_PROC_ALLOWLIST:
            continue
        suspects.append("pid=%s %s -> %s" % (pid, comm, args[:120]))

    rc2, listen, _ = run("ss -tulpnH 2>/dev/null | head -60", timeout=20)

    if not suspects:
        status = PASS
        actual = "Khong phat hien ung dung nghiep vu chay duoi user root"
    else:
        status = WARN
        actual = "Co %d tien trinh root ngoai danh sach daemon he thong chuan, can review: %s" % (
            len(suspects), "; ".join(s.split(" -> ")[0] for s in suspects[:10])
        )
    evidence = "Tien trinh root can review:\n" + ("\n".join(suspects) or "(khong co)") + "\n\nCong dang lang nghe:\n" + (listen or "")
    return status, actual, truncate(evidence)


def check_os09_root_ssh(cfg, facts):
    sshd, err = parse_sshd_config()
    if not sshd:
        return ERROR, "Khong doc duoc cau hinh sshd (sshd -T)", err
    val = sshd.get("permitrootlogin", "?")
    status = PASS if val == "no" else FAIL
    return status, "PermitRootLogin = %s" % val, ""


def _ufw_report():
    rc, out, _ = run("ufw status verbose 2>/dev/null", timeout=20)
    rc2, numbered, _ = run("ufw status numbered 2>/dev/null", timeout=20)
    return out or "", numbered or ""


def check_os10_firewall(cfg, facts):
    if has_cmd("ufw"):
        verbose, numbered = _ufw_report()
        active = re.search(r"^Status:\s*active", verbose, re.M) is not None
        m = re.search(r"^Default:\s*(.+)$", verbose, re.M)
        defaults = m.group(1).strip() if m else ""
        deny_in = "deny (incoming)" in defaults

        rule_lines = [
            l for l in numbered.splitlines()
            if re.match(r"^\[\s*\d+\]", l.strip())
        ]
        no_comment = [l.strip() for l in rule_lines if "#" not in l]

        problems = []
        if not active:
            problems.append("ufw khong active")
        if not deny_in:
            problems.append("default incoming khong phai DENY (%s)" % (defaults or "?"))
        if no_comment:
            problems.append("%d rule khong co comment giai thich" % len(no_comment))

        status = PASS if not problems else FAIL
        actual = "ufw active=%s | default=%s | so rule=%d | rule thieu comment=%d" % (
            active, defaults or "?", len(rule_lines), len(no_comment)
        )
        if problems:
            actual += " | Van de: " + "; ".join(problems)
        return status, actual, truncate(verbose + "\n" + numbered)

    # khong co ufw -> kiem tra nftables/iptables
    rc, nft, _ = run("nft list ruleset 2>/dev/null", timeout=20)
    rc2, ipt, _ = run("iptables -S 2>/dev/null", timeout=20)
    has_rules = bool((nft or "").strip()) or len([l for l in (ipt or "").splitlines() if l.startswith("-A")]) > 0
    status = PASS if has_rules else FAIL
    actual = "Khong cai ufw. %s" % ("Phat hien rule netfilter dang hieu luc." if has_rules else "KHONG co rule firewall nao.")
    return status, actual, truncate((nft or "") + "\n" + (ipt or ""))


def check_os11_filemax(cfg, facts):
    cur = sysctl_get("fs.file-max")
    ram_gb = facts.get("ram_gb", 0)
    expected = 71680 * ram_gb if ram_gb else 0
    try:
        cur_i = int(cur)
    except (TypeError, ValueError):
        return ERROR, "Khong doc duoc fs.file-max", ""
    status = PASS if expected and cur_i >= expected else FAIL
    actual = "fs.file-max = %d | RAM = %d GB -> yeu cau toi thieu %d" % (cur_i, ram_gb, expected)
    return status, actual, "Cong thuc sizing: 71680 x so GB RAM (8GB=573440, 16GB=1146880, 32GB=2293760, 64GB=4587520)"


def check_os12_bonding(cfg, facts):
    if facts.get("is_virtual"):
        return NA, "May ao (%s) - muc nay chi ap dung server vat ly" % facts.get("virtualization"), ""
    bonds = sorted(glob.glob("/proc/net/bonding/*"))
    if not bonds:
        return FAIL, "Server vat ly nhung khong co interface bonding nao", ""
    details = []
    ok = True
    for b in bonds:
        content = read_file(b) or ""
        slaves = re.findall(r"^Slave Interface:\s*(\S+)", content, re.M)
        up = re.findall(r"^MII Status:\s*(\S+)", content, re.M)
        mode = re.search(r"^Bonding Mode:\s*(.+)$", content, re.M)
        details.append("%s mode=%s slaves=%s status=%s" % (
            os.path.basename(b), mode.group(1).strip() if mode else "?", ",".join(slaves), ",".join(up)
        ))
        if len(slaves) < 2 or any(s != "up" for s in up):
            ok = False
    status = PASS if ok else FAIL
    return status, " | ".join(details), ""


def check_os13_multipath(cfg, facts):
    fc_hosts = sorted(glob.glob("/sys/class/fc_host/host*"))
    if not fc_hosts and not has_cmd("multipath"):
        return NA, "Khong co HBA FC va khong cai multipath-tools - may khong dung SAN", ""
    port_states = []
    for h in fc_hosts:
        st = (read_file(os.path.join(h, "port_state")) or "?").strip()
        port_states.append("%s=%s" % (os.path.basename(h), st))
    rc, mp, _ = run("multipath -ll 2>/dev/null", timeout=30)
    active, enabled = unit_state("multipathd")
    n_paths = len(re.findall(r"\bactive ready running\b", mp or ""))
    problems = []
    if fc_hosts and any("Online" not in s for s in port_states):
        problems.append("co cong FC khong Online")
    if active != "active":
        problems.append("multipathd khong active (%s)" % active)
    if n_paths < 2:
        problems.append("so path active < 2 (%d)" % n_paths)
    status = PASS if not problems else FAIL
    actual = "FC ports: %s | multipathd=%s | path active=%d" % (
        ", ".join(port_states) or "khong co", active, n_paths
    )
    if problems:
        actual += " | Van de: " + "; ".join(problems)
    return status, actual, truncate(mp or "")


def check_os14_kdump(cfg, facts):
    cmdline = read_file("/proc/cmdline") or ""
    has_crashkernel = "crashkernel=" in cmdline
    active, enabled = unit_state("kdump-tools")
    if active == "not-installed":
        active, enabled = unit_state("kdump")
    rc, show, _ = run("kdump-config show 2>/dev/null || kdumpctl status 2>/dev/null", timeout=20)
    ready = "current state" in (show or "").lower() and "ready to kdump" in (show or "").lower()

    problems = []
    if not has_crashkernel:
        problems.append("kernel cmdline thieu crashkernel=")
    if active != "active":
        problems.append("service kdump khong active (%s)" % active)
    if not ready and active == "active":
        problems.append("kdump chua o trang thai 'ready to kdump'")

    status = PASS if not problems else FAIL
    actual = "crashkernel=%s | kdump active=%s enabled=%s" % (
        "co" if has_crashkernel else "khong", active, enabled
    )
    if problems:
        actual += " | Van de: " + "; ".join(problems)
    return status, actual, truncate("/proc/cmdline: %s\n\n%s" % (cmdline.strip(), show or ""))


def check_os15_mta(cfg, facts):
    details = []
    bad = []
    for unit in ("sendmail", "postfix", "exim4"):
        a, e = unit_state(unit)
        if a == "not-installed":
            details.append("%s: khong cai dat" % unit)
            continue
        details.append("%s: active=%s enabled=%s" % (unit, a, e))
        if a == "active" or e == "enabled":
            bad.append(unit)
    status = PASS if not bad else FAIL
    actual = " | ".join(details)
    if bad:
        actual += " | VI PHAM: %s dang bat" % ", ".join(bad)
    return status, actual, ""


def check_os16_trace_sudo(cfg, facts):
    rules = sudoers_effective_lines()
    trace_bins = ("traceroute", "tcptraceroute")
    found = []
    for r in rules:
        line = r["line"]
        if "NOPASSWD" in line.upper() and any(b in line for b in trace_bins):
            found.append("%s: %s" % (r["file"], line))
    status = PASS if found else FAIL
    actual = ("Da cap quyen trace khong can password: " + " || ".join(found)) if found else (
        "Chua cap quyen NOPASSWD cho traceroute/tcptraceroute"
    )
    which = []
    for b in ("traceroute", "tcptraceroute", "iotop", "tcpdump", "lsof"):
        p = shutil.which(b)
        which.append("%s=%s" % (b, p or "khong co"))
    return status, actual, " | ".join(which)


def check_os17_networkmanager(cfg, facts):
    active, enabled = unit_state("NetworkManager")
    osid = facts.get("os_id", "")
    ver = facts.get("os_version_id", "")
    legacy = osid in ("centos", "rhel") and version_tuple(ver) < (7,)
    if not legacy:
        return NA, "OS = %s %s - theo checklist 'Linux 7: Khong xet'. NetworkManager active=%s" % (
            osid, ver, active
        ), ""
    status = PASS if active != "active" else FAIL
    return status, "NetworkManager active=%s enabled=%s (Linux 6 yeu cau tat)" % (active, enabled), ""


def check_os18_virtual_nic(cfg, facts):
    rc, out, _ = run("ip -br link 2>/dev/null", timeout=15)
    bad = []
    all_if = []
    for line in (out or "").splitlines():
        name = line.split()[0].split("@")[0] if line.split() else ""
        if not name:
            continue
        all_if.append(name)
        if name.startswith("virbr"):
            bad.append(name)
    status = PASS if not bad else FAIL
    actual = ("Ton tai card mang ao: %s" % ", ".join(bad)) if bad else "Khong co card mang ao thua (virbr*)"
    return status, actual, "Interface: %s" % ", ".join(all_if)


def check_os20_selinux(cfg, facts):
    if not has_cmd("getenforce") and not os.path.exists("/etc/selinux/config"):
        return PASS, "SELinux khong duoc cai dat tren he thong (khong kich hoat)", ""
    rc, cur, _ = run("getenforce 2>/dev/null", timeout=10)
    conf = ""
    for line in read_lines("/etc/selinux/config"):
        s = line.strip()
        if s.startswith("SELINUX="):
            conf = s.split("=", 1)[1].strip()
    runtime = (cur or "").strip()
    ok = runtime.lower() in ("disabled", "") and conf.lower() in ("disabled", "")
    status = PASS if ok else FAIL
    return status, "getenforce=%s | /etc/selinux/config SELINUX=%s" % (runtime or "n/a", conf or "n/a"), ""


def _conntrack_max():
    for key in ("net.netfilter.nf_conntrack_max", "net.nf_conntrack_max", "net.ipv4.netfilter.ip_conntrack_max"):
        v = sysctl_get(key)
        if v:
            return key, v
    return None, None


def check_os21_conntrack_max(cfg, facts):
    key, val = _conntrack_max()
    if val is None:
        return FAIL, "Module nf_conntrack chua duoc nap - khong doc duoc nf_conntrack_max (yeu cau >= %d)" % cfg["conntrack_max_min"], ""
    try:
        cur = int(val)
    except ValueError:
        return ERROR, "Gia tri khong hop le: %s" % val, ""
    status = PASS if cur >= cfg["conntrack_max_min"] else FAIL
    return status, "%s = %d (yeu cau >= %d)" % (key, cur, cfg["conntrack_max_min"]), ""


def check_os22_conntrack_hashsize(cfg, facts):
    val = read_file("/sys/module/nf_conntrack/parameters/hashsize")
    if val is None:
        val = read_file("/sys/module/ip_conntrack/parameters/hashsize")
    if val is None:
        return FAIL, "Module nf_conntrack chua duoc nap - khong doc duoc hashsize (yeu cau %d)" % cfg["conntrack_hashsize"], ""
    try:
        cur = int(val.strip())
    except ValueError:
        return ERROR, "Gia tri khong hop le: %s" % val, ""
    want = cfg["conntrack_hashsize"]
    status = PASS if cur >= want else FAIL
    return status, "nf_conntrack hashsize = %d (yeu cau >= %d = conntrack_max/4)" % (cur, want), ""


def check_os23_pw_expire(cfg, facts):
    shadow = shadow_map()
    if not shadow:
        return ERROR, "Khong doc duoc /etc/shadow (can quyen root)", ""
    users = [u for u in get_login_users() if u["uid"] >= 1000 and u["name"] != "nobody"]
    bad = []
    details = []
    for u in users:
        rec = shadow.get(u["name"])
        if not rec:
            continue
        maxdays = rec[4].strip()
        details.append("%s: max=%s" % (u["name"], maxdays or "(khong gioi han)"))
        if maxdays not in ("", "99999"):
            bad.append("%s(max=%s)" % (u["name"], maxdays))
    status = PASS if not bad else FAIL
    actual = ("User co mat khau het han: %s" % ", ".join(bad)) if bad else (
        "Tat ca user uid>=1000 deu khong bi het han mat khau"
    )
    return status, actual, " | ".join(details)


def _limit_domains(cfg):
    domains = ["*", "root"]
    for u in cfg.get("business_users") or []:
        if u not in domains:
            domains.append(u)
    return domains


def check_os24_nofile(cfg, facts):
    entries = limits_effective()
    ok, details = limits_check(entries, "nofile", cfg["nofile_min"], _limit_domains(cfg))
    status = PASS if ok else FAIL
    actual = "nofile (yeu cau >= %d): %s" % (cfg["nofile_min"], "dat" if ok else "CHUA dat")
    return status, actual, " | ".join(details)


def check_os25_nproc(cfg, facts):
    entries = limits_effective()
    ok, details = limits_check(entries, "nproc", cfg["nproc_min"], _limit_domains(cfg))
    status = PASS if ok else FAIL
    actual = "nproc (yeu cau >= %d): %s" % (cfg["nproc_min"], "dat" if ok else "CHUA dat")
    return status, actual, " | ".join(details)


def check_os26_extra_services(cfg, facts):
    units = ("cups", "cups-browsed", "bluetooth", "avahi-daemon")
    details = []
    bad = []
    for unit in units:
        a, e = unit_state(unit)
        if a == "not-installed":
            details.append("%s: khong cai dat" % unit)
            continue
        details.append("%s: active=%s enabled=%s" % (unit, a, e))
        if a == "active" or e == "enabled":
            bad.append(unit)
    status = PASS if not bad else FAIL
    actual = " | ".join(details)
    if bad:
        actual += " | VI PHAM: %s van dang bat" % ", ".join(bad)
    return status, actual, ""


def check_os27_pam_wheel(cfg, facts):
    found = None
    for line in read_lines("/etc/pam.d/su"):
        s = line.strip()
        if s.startswith("#") or "pam_wheel.so" not in s:
            continue
        parts = s.split()
        if len(parts) >= 3 and parts[0] == "auth" and parts[1] in ("required", "requisite"):
            found = s
            break
    wheel_members = ""
    for line in read_lines("/etc/group"):
        if line.startswith("wheel:"):
            wheel_members = line.split(":")[-1].strip()
    status = PASS if found else FAIL
    actual = ("Da cau hinh: %s" % found) if found else "/etc/pam.d/su chua co dong 'auth required pam_wheel.so use_uid'"
    return status, actual, "Thanh vien group wheel: %s" % (wheel_members or "(trong hoac group chua ton tai)")


def check_os28_pw_policy(cfg, facts):
    want = {"minlen": 8, "dcredit": -1, "ucredit": -1, "lcredit": -1, "ocredit": -1}
    have = {}
    for line in read_lines("/etc/security/pwquality.conf") + sum(
        (read_lines(p) for p in sorted(glob.glob("/etc/security/pwquality.conf.d/*.conf"))), []
    ):
        s = line.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        k, _, v = s.partition("=")
        have[k.strip()] = v.strip()

    pam_files = ["/etc/pam.d/common-password", "/etc/pam.d/system-auth", "/etc/pam.d/password-auth"]
    pam_lines = []
    for p in pam_files:
        for line in read_lines(p):
            s = line.strip()
            if s and not s.startswith("#"):
                pam_lines.append((p, s))

    has_pwquality = any("pam_pwquality.so" in s or "pam_cracklib.so" in s for _, s in pam_lines)
    pwhistory = None
    for _, s in pam_lines:
        if "pam_pwhistory.so" in s:
            m = re.search(r"remember=(\d+)", s)
            pwhistory = int(m.group(1)) if m else 0
        elif "pam_unix.so" in s and "remember=" in s and pwhistory is None:
            m = re.search(r"remember=(\d+)", s)
            pwhistory = int(m.group(1)) if m else 0

    problems = []
    for k, v in want.items():
        cur = have.get(k)
        if cur is None:
            problems.append("thieu %s (mong doi %s)" % (k, v))
            continue
        try:
            cur_i = int(cur)
        except ValueError:
            problems.append("%s=%s khong hop le" % (k, cur))
            continue
        if k == "minlen":
            if cur_i < v:
                problems.append("minlen=%d < %d" % (cur_i, v))
        else:
            if cur_i > v:
                problems.append("%s=%d (mong doi <= %d)" % (k, cur_i, v))
    if not has_pwquality:
        problems.append("PAM chua nap pam_pwquality.so")
    if pwhistory is None:
        problems.append("chua cau hinh pam_pwhistory (remember=5)")
    elif pwhistory < 5:
        problems.append("pwhistory remember=%d < 5" % pwhistory)

    status = PASS if not problems else FAIL
    actual = "pwquality: %s | pwhistory remember=%s" % (
        ", ".join("%s=%s" % (k, have.get(k, "-")) for k in ("minlen", "dcredit", "ucredit", "lcredit", "ocredit", "difok")),
        pwhistory if pwhistory is not None else "chua co",
    )
    if problems:
        actual += " | Van de: " + "; ".join(problems)
    return status, actual, truncate("\n".join("%s: %s" % (p, s) for p, s in pam_lines))


def check_os29_pw_hash(cfg, facts):
    encrypt = ""
    for line in read_lines("/etc/login.defs"):
        s = line.strip()
        if s.startswith("ENCRYPT_METHOD"):
            encrypt = s.split(None, 1)[1].strip() if len(s.split(None, 1)) > 1 else ""
    pam_ok = False
    pam_line = ""
    for p in ("/etc/pam.d/common-password", "/etc/pam.d/system-auth"):
        for line in read_lines(p):
            s = line.strip()
            if s.startswith("#") or "pam_unix.so" not in s:
                continue
            pam_line = s
            if "sha512" in s or "yescrypt" in s:
                pam_ok = True

    shadow = shadow_map()
    algos = {}
    for name, rec in shadow.items():
        pw = rec[1]
        if pw.startswith("$"):
            algos[pw.split("$")[1]] = algos.get(pw.split("$")[1], 0) + 1
    weak = [a for a in algos if a in ("1", "2", "2a", "5")]

    problems = []
    if encrypt.upper() not in ("SHA512", "YESCRYPT"):
        problems.append("ENCRYPT_METHOD=%s (mong doi SHA512)" % (encrypt or "chua dat"))
    if not pam_ok:
        problems.append("pam_unix.so chua dung sha512/yescrypt")
    if weak:
        problems.append("con hash yeu trong /etc/shadow: %s" % ", ".join("$%s$" % a for a in weak))

    status = PASS if not problems else FAIL
    actual = "ENCRYPT_METHOD=%s | pam_unix: %s | thuat toan dang dung trong shadow: %s" % (
        encrypt or "chua dat",
        "sha512/yescrypt" if pam_ok else "khac",
        ", ".join("$%s$ x%d" % (a, n) for a, n in sorted(algos.items())) or "khong co",
    )
    if problems:
        actual += " | Van de: " + "; ".join(problems)
    return status, actual, pam_line


def check_os30_sshd(cfg, facts):
    sshd, err = parse_sshd_config()
    if not sshd:
        return ERROR, "Khong doc duoc cau hinh sshd (sshd -T)", err

    problems = []
    checks = []

    def want(key, expected, cmp="eq"):
        cur = sshd.get(key, "")
        ok = False
        if cmp == "eq":
            ok = cur == str(expected)
        elif cmp == "lte":
            try:
                ok = int(cur) <= int(expected)
            except ValueError:
                ok = False
        elif cmp == "gte":
            try:
                ok = int(cur) >= int(expected)
            except ValueError:
                ok = False
        checks.append("%s=%s" % (key, cur or "?"))
        if not ok:
            problems.append("%s=%s (mong doi %s %s)" % (key, cur or "chua dat", cmp, expected))

    want("permitrootlogin", "no")
    want("permitemptypasswords", "no")
    want("maxauthtries", cfg["ssh_max_auth_tries"], "lte")
    want("clientaliveinterval", cfg["ssh_client_alive_interval"], "eq")
    want("clientalivecountmax", cfg["ssh_client_alive_count_max"], "eq")
    want("x11forwarding", "no")

    macs = [m.strip() for m in sshd.get("macs", "").split(",") if m.strip()]
    weak_macs = [m for m in macs if m not in STRONG_MACS]
    checks.append("macs=%d thuat toan" % len(macs))
    if weak_macs:
        problems.append("MACs con thuat toan yeu: %s" % ", ".join(weak_macs[:6]))

    status = PASS if not problems else FAIL
    actual = " | ".join(checks)
    if problems:
        actual += " | Van de: " + "; ".join(problems)
    return status, actual, truncate("MACs hieu luc:\n" + "\n".join(macs))


def check_os31_tmout(cfg, facts):
    files = ["/etc/profile"] + sorted(glob.glob("/etc/profile.d/*.sh"))
    found = []
    value = None
    readonly = False
    for p in files:
        for line in read_lines(p):
            s = line.strip()
            if s.startswith("#") or "TMOUT" not in s:
                continue
            found.append("%s: %s" % (p, s))
            m = re.search(r"TMOUT\s*=\s*(\d+)", s)
            if m:
                value = int(m.group(1))
            if s.startswith("readonly TMOUT"):
                readonly = True

    problems = []
    if value is None:
        problems.append("chua cau hinh TMOUT")
    elif value == 0 or value > cfg["tmout"]:
        problems.append("TMOUT=%d (mong doi <= %d va khac 0)" % (value, cfg["tmout"]))
    if value is not None and not readonly:
        problems.append("TMOUT chua duoc dat readonly (user co the ghi de)")

    status = PASS if not problems else FAIL
    actual = "TMOUT=%s readonly=%s" % (value if value is not None else "chua co", readonly)
    if problems:
        actual += " | Van de: " + "; ".join(problems)
    return status, actual, "\n".join(found)


def check_os32_unowned(cfg, facts):
    if not cfg.get("unowned_scan", True):
        return MANUAL, "Da tat quet file unowner trong cau hinh", ""
    timeout = int(cfg.get("unowned_scan_timeout", 120))
    rc, out, err = run(
        r"find / -xdev \( -nouser -o -nogroup \) -print 2>/dev/null | head -500",
        timeout=timeout,
    )
    if rc == 124:
        return WARN, "Qua thoi gian quet %ds - he thong file qua lon, can quet thu cong" % timeout, err
    files = [l for l in (out or "").splitlines() if l.strip()]
    status = PASS if not files else FAIL
    actual = ("Khong co file unowner" if not files else "Phat hien %d file/thu muc unowner (hien thi toi da 500)" % len(files))
    return status, actual, truncate("\n".join(files))


def check_os33_path(cfg, facts):
    candidates = []
    env_path = os.environ.get("PATH", "")
    candidates.append(("runtime PATH", env_path))
    for line in read_lines("/etc/environment"):
        s = line.strip()
        if s.startswith("PATH="):
            candidates.append(("/etc/environment", s.split("=", 1)[1].strip().strip('"')))
    for p in ["/etc/profile"] + sorted(glob.glob("/etc/profile.d/*.sh")) + ["/root/.bashrc", "/root/.profile"]:
        for line in read_lines(p):
            s = line.strip()
            if s.startswith("#"):
                continue
            m = re.match(r"(?:export\s+)?PATH=(.+)$", s)
            if m:
                candidates.append((p, m.group(1).strip().strip('"')))

    problems = []
    for src, value in candidates:
        if not value:
            continue
        entries = value.split(":")
        for e in entries:
            e_stripped = e.strip()
            if e_stripped in ("", "."):
                problems.append("%s: chua duong dan rong hoac '.' -> %s" % (src, value))
                break
            if e_stripped.startswith("/tmp") or e_stripped.startswith("/var/tmp"):
                problems.append("%s: chua /tmp -> %s" % (src, value))
                break

    status = PASS if not problems else FAIL
    actual = "Khong phat hien PATH nguy hiem" if not problems else "; ".join(problems)
    return status, actual, truncate("\n".join("%s = %s" % (s, v) for s, v in candidates))


def check_os34_cron_files(cfg, facts):
    allow = os.path.exists("/etc/cron.allow")
    deny = os.path.exists("/etc/cron.deny")
    perms = []
    for p in ("/etc/cron.allow", "/etc/cron.deny"):
        if os.path.exists(p):
            st = os.stat(p)
            perms.append("%s mode=%s uid=%d gid=%d" % (p, oct(st.st_mode & 0o777), st.st_uid, st.st_gid))
    problems = []
    if not allow:
        problems.append("thieu /etc/cron.allow")
    if deny:
        problems.append("van ton tai /etc/cron.deny")
    status = PASS if not problems else FAIL
    actual = "cron.allow: %s | cron.deny: %s" % ("co" if allow else "khong", "co" if deny else "khong")
    if problems:
        actual += " | Van de: " + "; ".join(problems)
    content = read_file("/etc/cron.allow") or ""
    return status, actual, " | ".join(perms) + ("\nNoi dung cron.allow:\n" + content if content else "")


def check_os35_rsyslog(cfg, facts):
    active, enabled = unit_state("rsyslog")
    conf_files = ["/etc/rsyslog.conf"] + sorted(glob.glob("/etc/rsyslog.d/*.conf"))
    forwards = []
    for p in conf_files:
        for line in read_lines(p):
            s = line.strip()
            if s.startswith("#") or not s:
                continue
            if re.search(r"@@?\[?[\w\.\-:]+", s) and (s.startswith("*.") or "action(" in s or s.startswith("auth") or s.startswith("authpriv")):
                forwards.append("%s: %s" % (os.path.basename(p), s))

    problems = []
    if active != "active":
        problems.append("rsyslog khong active (%s)" % active)
    if enabled != "enabled":
        problems.append("rsyslog chua enabled (%s)" % enabled)
    want_servers = cfg.get("log_servers") or []
    if want_servers:
        missing = [s for s in want_servers if not any(s in f for f in forwards)]
        if missing:
            problems.append("chua forward log toi: %s" % ", ".join(missing))
    elif not forwards:
        problems.append("chua cau hinh forward log ve log server tap trung")

    status = PASS if not problems else FAIL
    actual = "rsyslog active=%s enabled=%s | so rule forward=%d" % (active, enabled, len(forwards))
    if problems:
        actual += " | Van de: " + "; ".join(problems)
    return status, actual, truncate("\n".join(forwards))


def check_os36_iptables(cfg, facts):
    rc, ipt, _ = run("iptables -S 2>/dev/null", timeout=20)
    rc2, nft, _ = run("nft list ruleset 2>/dev/null", timeout=20)
    ufw_active = False
    if has_cmd("ufw"):
        rc3, out, _ = run("ufw status 2>/dev/null", timeout=15)
        ufw_active = "Status: active" in (out or "")

    rules = [l for l in (ipt or "").splitlines() if l.startswith("-A")]
    input_policy = ""
    for l in (ipt or "").splitlines():
        if l.startswith("-P INPUT"):
            input_policy = l.split()[-1]

    has_protection = ufw_active or len(rules) > 0 or bool((nft or "").strip())
    open_policy = input_policy == "ACCEPT" and not ufw_active and len(rules) == 0

    status = PASS if (has_protection and not open_policy) else FAIL
    actual = "ufw active=%s | iptables INPUT policy=%s | so rule=%d | nftables ruleset=%s" % (
        ufw_active, input_policy or "?", len(rules), "co" if (nft or "").strip() else "khong"
    )
    return status, actual, truncate(ipt or "")


def check_os38_zone_reclaim(cfg, facts):
    val = sysctl_get("vm.zone_reclaim_mode")
    if val is None:
        return ERROR, "Khong doc duoc vm.zone_reclaim_mode", ""
    status = PASS if val.strip() == "0" else FAIL
    return status, "vm.zone_reclaim_mode = %s (yeu cau 0)" % val.strip(), ""


def check_os39_openssl(cfg, facts):
    rc, out, _ = run("openssl version 2>/dev/null", timeout=15)
    if rc != 0 or not out:
        return FAIL, "Khong tim thay openssl tren he thong", ""
    m = re.search(r"OpenSSL\s+(\S+)", out)
    ver = m.group(1) if m else ""
    minv = cfg.get("openssl_min_version", "1.1.1")
    ok = version_tuple(ver) >= version_tuple(minv)
    rc2, full, _ = run("openssl version -a 2>/dev/null", timeout=15)
    status = PASS if ok else FAIL
    return status, "%s (yeu cau toi thieu %s)" % (out, minv), truncate(full or "")


def check_os41_repo(cfg, facts):
    hosts = cfg.get("internal_repo_hosts") or []
    uris = []
    files = ["/etc/apt/sources.list"] + sorted(
        glob.glob("/etc/apt/sources.list.d/*.list") + glob.glob("/etc/apt/sources.list.d/*.sources")
    )
    for p in files:
        for line in read_lines(p):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if s.startswith("deb") or s.startswith("URIs:"):
                for m in re.findall(r"https?://([^/\s]+)", s):
                    uris.append(m)
    uris = sorted(set(uris))
    if not hosts:
        return MANUAL, "Chua khai bao repo noi bo trong Cau hinh. Repo dang dung: %s" % (
            ", ".join(uris) or "khong co"
        ), ""
    external = [u for u in uris if not any(h in u for h in hosts)]
    status = PASS if not external else FAIL
    actual = "Repo dang dung: %s" % (", ".join(uris) or "khong co")
    if external:
        actual += " | VI PHAM: repo ngoai danh sach noi bo: %s" % ", ".join(external)
    return status, actual, ""


def check_os42_sysctl(cfg, facts):
    guideline = cfg.get("sysctl_guideline") or {}
    mismatched = []
    details = []
    for key, want in sorted(guideline.items()):
        cur = sysctl_get(key)
        details.append("%s = %s (mong doi %s)" % (key, cur if cur is not None else "n/a", want))
        if cur is None:
            mismatched.append("%s (khong doc duoc)" % key)
        elif cur.strip() != str(want).strip():
            mismatched.append("%s=%s" % (key, cur.strip()))
    status = PASS if not mismatched else FAIL
    actual = "Dat %d/%d tham so guideline" % (len(guideline) - len(mismatched), len(guideline))
    if mismatched:
        actual += " | Lech: " + ", ".join(mismatched)
    return status, actual, "\n".join(details)


def check_os45_lldpd(cfg, facts):
    if facts.get("is_virtual"):
        return NA, "May ao (%s) - LLDPD chi bat buoc voi may chu vat ly" % facts.get("virtualization"), ""
    active, enabled = unit_state("lldpd")
    if active == "not-installed":
        return FAIL, "Chua cai goi lldpd tren may chu vat ly", ""
    rc, nb, _ = run("lldpcli show neighbors 2>/dev/null", timeout=20)
    has_nb = "Interface:" in (nb or "")
    problems = []
    if active != "active":
        problems.append("lldpd khong active (%s)" % active)
    if not has_nb:
        problems.append("lldpcli show neighbors khong tra ve neighbor nao")
    status = PASS if not problems else FAIL
    actual = "lldpd active=%s enabled=%s | neighbors: %s" % (active, enabled, "co" if has_nb else "khong")
    if problems:
        actual += " | Van de: " + "; ".join(problems)
    return status, actual, truncate(nb or "")


# ------------------------------------------------- cac muc danh gia thu cong


def check_manual_virt(cfg, facts):
    return MANUAL, "Kiem tra tren he thong quan ly ao hoa (vCenter/OpenStack) - ngoai pham vi agent OS", ""


def check_os19_license(cfg, facts):
    rc, out, _ = run("pro status --format json 2>/dev/null || subscription-manager status 2>/dev/null", timeout=25)
    return MANUAL, "Can doi chieu hop dong/ban quyen OS. Thong tin thu thap duoc o phan evidence.", truncate(out or "(khong co cong cu quan ly license)")


def check_os37_siem(cfg, facts):
    hints = []
    for path in ("/opt/se/salt-call", "/opt/se", "/etc/salt/minion"):
        if os.path.exists(path):
            hints.append("ton tai %s" % path)
    for unit in ("salt-minion", "wazuh-agent", "ossec", "filebeat", "auditbeat"):
        a, e = unit_state(unit)
        if a != "not-installed":
            hints.append("%s active=%s enabled=%s" % (unit, a, e))
    return MANUAL, "Do team NOC-SOC xac nhan. Dau hieu agent phat hien duoc: %s" % (
        "; ".join(hints) or "khong phat hien agent SIRC/SIEM nao"
    ), ""


def check_os40_monitoring(cfg, facts):
    hints = []
    for unit in ("node_exporter", "prometheus-node-exporter", "ncms-agent", "zabbix-agent", "zabbix-agent2"):
        a, e = unit_state(unit)
        if a != "not-installed":
            hints.append("%s active=%s enabled=%s" % (unit, a, e))
    rc, out, _ = run("ss -tulpnH 2>/dev/null | grep -E ':(9100|10050|9256)\\b'", timeout=20)
    if out:
        hints.append("cong giam sat dang lang nghe: %s" % out.replace("\n", " | ")[:300])
    return MANUAL, "Do team NOC-SOC xac nhan. Dau hieu agent giam sat: %s" % (
        "; ".join(hints) or "khong phat hien agent giam sat nao"
    ), ""


def check_os43_aam(cfg, facts):
    return MANUAL, "Danh gia tren phan mem AAM - ngoai pham vi agent OS", ""


def check_os44_storage(cfg, facts):
    rc, out, _ = run("df -hT -x tmpfs -x devtmpfs -x squashfs 2>/dev/null", timeout=20)
    return MANUAL, "Danh gia theo thiet ke/tai lieu quy hoach tai nguyen va giai phap backup", truncate(out or "")


# ---------------------------------------------------------------- dang ky check

CHECKS = [
    ("VIRT-01", check_manual_virt),
    ("VIRT-02", check_manual_virt),
    ("OS-01", check_os01_mount),
    ("OS-02", check_os02_timezone),
    ("OS-03", check_os03_ntp),
    ("OS-04", check_os04_crontab),
    ("OS-05", check_os05_users),
    ("OS-06", check_os06_sudo),
    ("OS-07", check_os07_uid0),
    ("OS-08", check_os08_root_apps),
    ("OS-09", check_os09_root_ssh),
    ("OS-10", check_os10_firewall),
    ("OS-11", check_os11_filemax),
    ("OS-12", check_os12_bonding),
    ("OS-13", check_os13_multipath),
    ("OS-14", check_os14_kdump),
    ("OS-15", check_os15_mta),
    ("OS-16", check_os16_trace_sudo),
    ("OS-17", check_os17_networkmanager),
    ("OS-18", check_os18_virtual_nic),
    ("OS-19", check_os19_license),
    ("OS-20", check_os20_selinux),
    ("OS-21", check_os21_conntrack_max),
    ("OS-22", check_os22_conntrack_hashsize),
    ("OS-23", check_os23_pw_expire),
    ("OS-24", check_os24_nofile),
    ("OS-25", check_os25_nproc),
    ("OS-26", check_os26_extra_services),
    ("OS-27", check_os27_pam_wheel),
    ("OS-28", check_os28_pw_policy),
    ("OS-29", check_os29_pw_hash),
    ("OS-30", check_os30_sshd),
    ("OS-31", check_os31_tmout),
    ("OS-32", check_os32_unowned),
    ("OS-33", check_os33_path),
    ("OS-34", check_os34_cron_files),
    ("OS-35", check_os35_rsyslog),
    ("OS-36", check_os36_iptables),
    ("OS-37", check_os37_siem),
    ("OS-38", check_os38_zone_reclaim),
    ("OS-39", check_os39_openssl),
    ("OS-40", check_os40_monitoring),
    ("OS-41", check_os41_repo),
    ("OS-42", check_os42_sysctl),
    ("OS-43", check_os43_aam),
    ("OS-44", check_os44_storage),
    ("OS-45", check_os45_lldpd),
]


def load_config():
    cfg = dict(DEFAULT_CONFIG)
    if len(sys.argv) > 1 and sys.argv[1].strip():
        try:
            raw = base64.b64decode(sys.argv[1]).decode("utf-8")
            user_cfg = json.loads(raw)
            for k, v in user_cfg.items():
                if k == "sysctl_guideline" and isinstance(v, dict) and v:
                    merged = dict(DEFAULT_CONFIG["sysctl_guideline"])
                    merged.update(v)
                    cfg[k] = merged
                elif v is not None:
                    cfg[k] = v
        except Exception as exc:  # noqa: BLE001
            cfg["_config_error"] = str(exc)
    return cfg


def main():
    started = time.time()
    cfg = load_config()
    facts = collect_facts()

    results = []
    for check_id, fn in CHECKS:
        t0 = time.time()
        try:
            status, actual, evidence = fn(cfg, facts)
        except Exception as exc:  # noqa: BLE001
            status, actual, evidence = ERROR, "Loi khi chay check: %s" % exc, ""
        results.append(
            {
                "id": check_id,
                "status": status,
                "actual": truncate(actual, 2000),
                "evidence": truncate(evidence, 6000),
                "duration_ms": int((time.time() - t0) * 1000),
            }
        )

    summary = {}
    for r in results:
        summary[r["status"]] = summary.get(r["status"], 0) + 1

    payload = {
        "schema": 1,
        "facts": facts,
        "config_applied": {k: v for k, v in cfg.items() if k != "sysctl_guideline"},
        "results": results,
        "summary": summary,
        "duration_ms": int((time.time() - started) * 1000),
    }
    sys.stdout.write("__HARDENING_JSON_START__\n")
    sys.stdout.write(json.dumps(payload, ensure_ascii=False))
    sys.stdout.write("\n__HARDENING_JSON_END__\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
