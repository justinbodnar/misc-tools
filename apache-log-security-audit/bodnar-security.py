"""Interactive LAMP security helper.

This tool consolidates the Apache log audit, SSH auth brute-force review,
SQL security audit, and a quick remote LAMP checklist behind a menu-driven
workflow. It prompts for required inputs, prints findings with actionable
recommendations, and can save run output into ./logs with optional rotation.
"""

from __future__ import annotations

import datetime
import getpass
import gzip
import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

# ---------- shared utilities ----------

BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "logs"
TMP_DIR = BASE_DIR / "tmp"

# Default scan parameters (edit these constants to customize behavior)
APACHE_LOG_DIR = Path("/var/log/apache2/")
APACHE_FILTER_FILE = Path("./apache-log-security-audit/default_filter.xml")
APACHE_MIN_IMPACT = 2
APACHE_MAX_MATCHES_PER_RULE = 25

AUTH_LOG_FILE = Path("/var/log/auth.log")
VAR_LOG_DIR = AUTH_LOG_FILE.parent
MASTER_LOG = TMP_DIR / "auth.log.MASTER"

DEFAULT_DB_CLIENT = "mysql"
DEFAULT_DB_HOST = "127.0.0.1"
DEFAULT_DB_PORTS = {"mysql": 3306, "mariadb": 3306, "psql": 5432}
DEFAULT_DB_USER = {"mysql": "root", "mariadb": "root", "psql": "postgres"}

DEFAULT_SSH_TARGET = ""  # Set to user@host for remote quick checks


def prompt(message: str, default: Optional[str] = None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    response = input(f"{message}{suffix}: ").strip()
    if not response and default is not None:
        return default
    return response


def confirm(message: str, default: bool = False) -> bool:
    default_text = "Y/n" if default else "y/N"
    response = input(f"{message} ({default_text}): ").strip().lower()
    if not response:
        return default
    return response.startswith("y")


def rotate_logs(directory: Path, keep_last: int = 5) -> None:
    if not directory.exists():
        print("[INFO] No logs directory to rotate.")
        return
    files = sorted(directory.glob("*.log"), key=lambda f: f.stat().st_mtime, reverse=True)
    if len(files) <= keep_last:
        print(f"[INFO] {len(files)} log file(s) present; nothing to rotate.")
        return
    for stale in files[keep_last:]:
        stale.unlink()
    print(f"[INFO] Rotated logs; kept {keep_last}, removed {len(files) - keep_last} old file(s).")


def save_log(lines: List[str], name: str, *, auto_rotate_keep: Optional[int] = None) -> Path:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    path = LOG_DIR / f"{name}-{timestamp}.log"
    path.write_text("\n".join(lines), encoding="utf-8")
    print(f"[INFO] Saved log to {path}")
    if auto_rotate_keep:
        rotate_logs(LOG_DIR, auto_rotate_keep)
    return path


def maybe_save_log(
    lines: List[str],
    name: str,
    *,
    interactive: bool = True,
    auto_rotate_keep: int = 5,
) -> Optional[Path]:
    if not lines:
        return None
    if not interactive and auto_rotate_keep < 1:
        auto_rotate_keep = 1

    if interactive:
        if not confirm("Save this report to ./logs?", default=True):
            return None
        keep_default = str(auto_rotate_keep)
        keep = prompt(
            "How many most recent log files should be kept (older files will be deleted)?",
            default=keep_default,
        )
        try:
            keep_value = int(keep)
        except ValueError:
            print("[WARN] Invalid number supplied; using default rotation setting.")
            keep_value = auto_rotate_keep
        path = save_log(lines, name, auto_rotate_keep=keep_value)
    else:
        path = save_log(lines, name, auto_rotate_keep=auto_rotate_keep)
    return path


# ---------- Apache access/error log audit ----------

VERBOSITY_LEVELS = {"quiet": 0, "info": 1, "debug": 2}


def load_filter_rules(filter_file: str, min_impact: int) -> List[Dict[str, object]]:
    if not os.path.exists(filter_file):
        print(f"[WARN] Filter file {filter_file} not found; skipping signature scan.")
        return []

    import xml.etree.ElementTree as ET

    tree = ET.parse(filter_file)
    root = tree.getroot()
    rules = []
    for filt in root.findall("filter"):
        try:
            impact = int(filt.findtext("impact", default="0"))
        except ValueError:
            impact = 0
        if impact < min_impact:
            continue
        rule_id = filt.findtext("id", default="unknown")
        description = filt.findtext("description", default="")
        rule_text = filt.findtext("rule", default="")
        tags = [tag.text for tag in filt.findall("tags/tag") if tag.text]
        try:
            pattern = re.compile(rule_text, re.IGNORECASE)
        except re.error:
            print(f"[WARN] Skipping invalid regex for rule {rule_id}.")
            continue
        rules.append(
            {
                "id": rule_id,
                "description": description,
                "impact": impact,
                "tags": tags,
                "pattern": pattern,
            }
        )
    print(f"[INFO] Loaded {len(rules)} filters with impact >= {min_impact}.")
    return rules


def scan_log_file(log_path: str, rules: List[Dict[str, object]], max_matches_per_rule: int) -> List[Dict[str, object]]:
    findings: List[Dict[str, object]] = []
    if not rules:
        return findings
    with open(log_path, "r", encoding="utf-8", errors="ignore") as handle:
        for line_no, line in enumerate(handle, start=1):
            for rule in rules:
                if rule.get("matched", 0) >= max_matches_per_rule:
                    continue
                if rule["pattern"].search(line):
                    rule["matched"] = rule.get("matched", 0) + 1
                    findings.append(
                        {
                            "rule_id": rule["id"],
                            "impact": rule["impact"],
                            "description": rule["description"],
                            "tags": rule["tags"],
                            "line_no": line_no,
                            "line": line.strip(),
                        }
                    )
    return findings


def write_scan_results(log_name: str, findings: List[Dict[str, object]], output_dir: Path) -> Optional[Path]:
    if not findings:
        return None
    output_dir.mkdir(exist_ok=True)
    output_path = output_dir / f"{log_name}_findings.txt"
    with output_path.open("w", encoding="utf-8") as handle:
        handle.write("Potentially malicious patterns identified in {0}\n".format(log_name))
        handle.write("=" * 80 + "\n\n")
        for finding in findings:
            tags = ",".join(finding.get("tags", []))
            handle.write(f"[{finding['rule_id']}] impact={finding['impact']} tags=[{tags}]\n")
            handle.write(f"{finding['description']}\n")
            handle.write(
                f"Line {finding['line_no']}: {finding['line']}\n" + "-" * 40 + "\n"
            )
    return output_path


def analyze_access_log(path: str) -> Dict[str, object]:
    summary = {
        "name": os.path.basename(path),
        "total": 0,
        "status_counts": Counter(),
        "ip_counts": Counter(),
        "ip_error_counts": Counter(),
        "suspicious_paths": Counter(),
        "warnings": [],
        "offenders": [],
    }
    suspicious_keywords = [
        "wp-login.php",
        "xmlrpc.php",
        ".env",
        "phpmyadmin",
        "wp-admin",
        ".git/",
        "HNAP1",
        "shell",
    ]
    pattern = re.compile(
        r"^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] \"(?P<request>[^\"]*)\" (?P<status>\d{3}) (?P<size>\S+)"
    )
    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            match = pattern.match(line)
            if not match:
                continue
            summary["total"] += 1
            status = match.group("status")
            request = match.group("request").lower()
            ip = match.group("ip")
            summary["status_counts"][status] += 1
            summary["ip_counts"][ip] += 1
            if status.startswith("4") or status.startswith("5"):
                summary["ip_error_counts"][ip] += 1
            for keyword in suspicious_keywords:
                if keyword in request:
                    summary["suspicious_paths"][keyword] += 1
    errors = sum(
        count for status, count in summary["status_counts"].items() if status.startswith("4") or status.startswith("5")
    )
    if summary["total"]:
        summary["error_rate"] = (errors / float(summary["total"])) * 100
    else:
        summary["error_rate"] = 0.0
    for ip, value in summary["ip_error_counts"].most_common():
        if value >= 50:
            summary["warnings"].append(f"IP {ip} generated {value} 4xx/5xx responses")
            summary["offenders"].append(
                {
                    "ip": ip,
                    "reason": f"generated {value} HTTP errors",
                    "error_count": value,
                }
            )
    for keyword, hits in summary["suspicious_paths"].most_common():
        if hits > 0:
            summary["warnings"].append(f"Observed {hits} requests for suspicious path '{keyword}'")
    if summary["error_rate"] > 10:
        summary["warnings"].append(f"High HTTP error rate ({summary['error_rate']:.2f}%)")
    return summary


def analyze_error_log(path: str) -> Dict[str, object]:
    keywords = {
        "client_denied": "client denied by server configuration",
        "file_missing": "File does not exist",
        "script_not_found": "script not found",
        "php_fatal": "PHP Fatal error",
        "php_warning": "PHP Warning",
        "segfault": "seg fault",
    }
    summary = {
        "name": os.path.basename(path),
        "counts": Counter(),
        "warnings": [],
    }
    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            lowered = line.lower()
            for key, keyword in keywords.items():
                if keyword.lower() in lowered:
                    summary["counts"][key] += 1
    for key, count in summary["counts"].items():
        if count:
            summary["warnings"].append(f"{count} occurrences of {key.replace('_', ' ')}")
    return summary


def print_behavior_report(access_reports: List[Dict[str, object]], error_reports: List[Dict[str, object]]) -> List[str]:
    lines: List[str] = []
    if not access_reports and not error_reports:
        lines.append("[INFO] No additional behavior summaries available.")
        return lines
    lines.extend([
        "",
        "####################################",
        "# HTTP log behavior summary report #",
        "####################################",
    ])
    for report in access_reports:
        lines.append(f"[REPORT][{report['name']}] {report['total']} requests | Error rate: {report['error_rate']:.2f}%")
        top_ips = ", ".join(f"{ip} ({count})" for ip, count in report["ip_counts"].most_common(3))
        if top_ips:
            lines.append(f"   Top talkers: {top_ips}")
        if report["warnings"]:
            for warning in report["warnings"]:
                lines.append(f"   [WARN] {warning}")
    for report in error_reports:
        lines.append(f"[REPORT][{report['name']}] Error breakdown: {dict(report['counts'])}")
        if report["warnings"]:
            for warning in report["warnings"]:
                lines.append(f"   [WARN] {warning}")
    return lines


def collect_offenders(access_reports: List[Dict[str, object]]) -> List[Dict[str, object]]:
    offenders: Dict[str, Dict[str, object]] = {}
    for report in access_reports:
        for offender in report.get("offenders", []):
            ip = offender["ip"]
            if ip not in offenders or offender.get("error_count", 0) > offenders[ip].get("error_count", 0):
                offenders[ip] = offender
    return list(offenders.values())


def print_enforcement_guidance(offenders: List[Dict[str, object]]) -> List[str]:
    lines: List[str] = []
    if not offenders:
        lines.append("\n[ACTION] No offending IPs crossed the alert threshold.")
        return lines
    lines.extend(
        [
            "",
            "########################################",
            "# Recommended response for bad actors   #",
            "########################################",
            "[ACTION] The following IPs generated excessive HTTP errors:",
        ]
    )
    for offender in offenders:
        ip = offender["ip"]
        lines.append(f" - {ip}: {offender['reason']}")
    ips = ", ".join(offender["ip"] for offender in offenders)
    lines.extend(
        [
            "",
            "[ACTION] Quick block examples:",
            "   sudo ufw deny from <IP> to any    # e.g., sudo ufw deny from 1.2.3.4",
            "   sudo iptables -I INPUT -s <IP> -j DROP",
            "   sudo ipset add blocked_ips <IP>   # if using ipset",
            "Replace <IP> with any of the following:",
            f"   {ips}",
        ]
    )
    return lines


def concatenate_logs(tmp_dir: Path) -> int:
    keys: Dict[str, List[str]] = {}
    for file in os.listdir(tmp_dir):
        elements = file.split(".")
        if len(elements) > 2:
            key = elements[0] + "." + elements[1] + "." + elements[2]
            last_index_added = 2
        else:
            key = elements[0] + "." + elements[1]
            last_index_added = 1
        key = key.lower()
        if "access" not in key and "error" not in key and len(elements) > last_index_added + 1:
            last_index_added += 1
            key = key + "." + elements[last_index_added]
        if elements[0] == "access" and elements[1] == "log":
            key = "access.log"
        if elements[0] == "error" and elements[1] == "log":
            key = "error.log"
        if key not in keys:
            keys[key] = []
        keys[key].append(file)
    print(f"[INFO] {len(keys)} distinct sites were found.")
    for key, file_list in keys.items():
        master_path = tmp_dir / f"{key}-MASTER"
        with open(master_path, "wb") as destination:
            for file in file_list:
                with open(tmp_dir / file, "rb") as source:
                    shutil.copyfileobj(source, destination)
                os.remove(tmp_dir / file)
    total_masters = len(os.listdir(tmp_dir))
    print(f"[INFO] {total_masters} master files were created.")
    return total_masters


def run_apache_log_audit(
    *, interactive: bool = True, auto_rotate_keep: int = 5
) -> Tuple[List[str], List[str], Optional[Path]]:
    lines: List[str] = []
    working_log_dir = APACHE_LOG_DIR
    filter_file = str(APACHE_FILTER_FILE) if APACHE_FILTER_FILE.exists() else ""
    min_impact = APACHE_MIN_IMPACT
    max_matches = APACHE_MAX_MATCHES_PER_RULE

    if not os.path.isdir(working_log_dir):
        print(f"[ERROR] {working_log_dir} doesn't exist.")
        return lines, [], None

    for folder in ("./output", TMP_DIR):
        if os.path.isdir(folder):
            shutil.rmtree(folder)
        os.makedirs(folder, exist_ok=True)
    print("[INFO] Using ./output directory for results")
    print("[INFO] Using ./tmp directory as workspace")

    source_files = [f for f in os.listdir(working_log_dir) if os.path.isfile(os.path.join(working_log_dir, f))]
    if not source_files:
        print(f"[ERROR] {working_log_dir} has 0 files to analyze")
        return lines, [], None
    for filename in source_files:
        shutil.copy2(os.path.join(working_log_dir, filename), TMP_DIR / filename)
    print(f"[INFO] Copied {len(os.listdir(TMP_DIR))} files to ./tmp directory")

    gzs = 0
    for filename in list(os.listdir(TMP_DIR)):
        if filename.endswith(".gz"):
            gz_path = TMP_DIR / filename
            target_path = TMP_DIR / filename[:-3]
            with gzip.open(gz_path, "rb") as gz_handle, open(target_path, "wb") as out:
                shutil.copyfileobj(gz_handle, out)
            os.remove(gz_path)
            gzs += 1
    print(f"[INFO] Decompressed {gzs} gunzip files")

    count = concatenate_logs(TMP_DIR)

    access_reports: List[Dict[str, object]] = []
    error_reports: List[Dict[str, object]] = []
    for master_file in os.listdir(TMP_DIR):
        path = TMP_DIR / master_file
        if "access" in master_file:
            access_reports.append(analyze_access_log(str(path)))
        elif "error" in master_file:
            error_reports.append(analyze_error_log(str(path)))
    lines.extend(print_behavior_report(access_reports, error_reports))
    offenders = collect_offenders(access_reports)
    lines.extend(print_enforcement_guidance(offenders))

    print("[INFO] Running signature search on master files.")
    rules: List[Dict[str, object]] = []
    if filter_file:
        rules = load_filter_rules(filter_file, min_impact)
    findings_summary = []
    for index, master_file in enumerate(os.listdir(TMP_DIR), start=1):
        print(f"[INFO] Processing file {index} of {count}: {master_file}")
        path = TMP_DIR / master_file
        findings = scan_log_file(str(path), rules, max_matches)
        output_path = write_scan_results(master_file, findings, Path("./output"))
        if output_path:
            findings_summary.append((master_file, len(findings), output_path))

    if not findings_summary:
        lines.append("[INFO] No evidence of hacking patterns found in master files.")
        lines.append("[EXITING] Success!")
    else:
        lines.append(f"[INFO] {len(findings_summary)} files contained suspicious patterns:")
        for item in findings_summary:
            lines.append(f" - {item[0]}: {item[1]} matches -> {item[2]}")

    shutil.rmtree(TMP_DIR)
    print("[EXIT] Apache log audit complete. Temporary data removed.")

    for entry in lines:
        print(entry)

    recommendations: List[str] = []
    if offenders:
        offender_ips = ", ".join(offender["ip"] for offender in offenders[:5])
        recommendations.append(f"Block or throttle abusive IPs observed in Apache logs: {offender_ips}.")
    if findings_summary:
        recommendations.append(
            "Review suspicious patterns noted in ./output findings and harden exposed paths (e.g., wp-login.php, phpMyAdmin)."
        )
    saved_path = maybe_save_log(
        lines,
        "apache-audit",
        interactive=interactive,
        auto_rotate_keep=auto_rotate_keep,
    )
    return lines, recommendations, saved_path


# ---------- auth.log brute-force audit ----------

FAILED_THRESHOLD = 25
SUDO_SAMPLE_LIMIT = 10

FAILED_PASSWORD_PATTERN = re.compile(r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>[0-9.]+)")
ACCEPTED_PASSWORD_PATTERN = re.compile(r"Accepted password for (?P<user>\S+) from (?P<ip>[0-9.]+)")
INVALID_USER_PATTERN = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[0-9.]+)")
AUTH_FAILURE_PATTERN = re.compile(r"authentication failure.*rhost=(?P<ip>[0-9.]+)")


def prepare_tmp_dir() -> None:
    if TMP_DIR.exists():
        shutil.rmtree(TMP_DIR)
    TMP_DIR.mkdir(parents=True)


def copy_logs_into_tmp(base: Path) -> List[Path]:
    sources = sorted(base.glob(f"{AUTH_LOG_FILE.name}*"))
    if not sources:
        print(f"[ERROR] No {AUTH_LOG_FILE.name} files found in {base}")
        return []

    copied: List[Path] = []
    for src in sources:
        dest = TMP_DIR / src.name
        shutil.copy2(src, dest)
        copied.append(dest)
    print(f"[INFO] Copied {len(copied)} files into {TMP_DIR}")
    return copied


def decompress_logs(files: Iterable[Path]) -> None:
    decompressed = 0
    for file in files:
        if file.suffix != ".gz":
            continue
        target = file.with_suffix("")
        with gzip.open(file, "rb") as src, open(target, "wb") as dst:
            shutil.copyfileobj(src, dst)
        file.unlink()
        decompressed += 1
    print(f"[INFO] Decompressed {decompressed} gzip archives")


def build_master_log() -> Path:
    with MASTER_LOG.open("wb") as dest:
        for file in sorted(TMP_DIR.iterdir()):
            if file == MASTER_LOG:
                continue
            with file.open("rb") as src:
                shutil.copyfileobj(src, dest)
    print("[INFO] Combined logs into tmp/auth.log.MASTER")
    for file in list(TMP_DIR.iterdir()):
        if file != MASTER_LOG:
            file.unlink()
    return MASTER_LOG


def prepare_master_log(base: Path) -> Optional[Path]:
    if not base.exists():
        print(f"[ERROR] {base} does not exist")
        return None
    prepare_tmp_dir()
    copied = copy_logs_into_tmp(base)
    if not copied:
        return None
    decompress_logs(copied)
    return build_master_log()


def analyze_auth_log(path: Path) -> dict:
    message_counts: Counter[str] = Counter()
    seen_ips: Counter[str] = Counter()
    failed_attempts_by_ip: Counter[str] = Counter()
    failed_attempts_by_user: Counter[str] = Counter()
    accepted_by_user: Counter[str] = Counter()
    accepted_by_ip: Counter[str] = Counter()
    invalid_user_targets: Counter[str] = Counter()
    authentication_failures: Counter[str] = Counter()
    sudo_commands: List[str] = []
    unknown_samples: List[str] = []

    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            ips = re.findall(r"[0-9]+(?:\.[0-9]+){3}", line)
            for ip in ips:
                seen_ips[ip] += 1

            failed_match = FAILED_PASSWORD_PATTERN.search(line)
            if failed_match:
                ip = failed_match.group("ip")
                user = failed_match.group("user")
                failed_attempts_by_ip[ip] += 1
                failed_attempts_by_user[user] += 1

            accepted_match = ACCEPTED_PASSWORD_PATTERN.search(line)
            if accepted_match:
                ip = accepted_match.group("ip")
                user = accepted_match.group("user")
                accepted_by_ip[ip] += 1
                accepted_by_user[user] += 1

            invalid_match = INVALID_USER_PATTERN.search(line)
            if invalid_match:
                invalid_user_targets[invalid_match.group("user")] += 1
                failed_attempts_by_ip[invalid_match.group("ip")] += 1

            auth_failure_match = AUTH_FAILURE_PATTERN.search(line)
            if auth_failure_match:
                authentication_failures[auth_failure_match.group("ip")] += 1

            categorize_line(line, message_counts, sudo_commands, unknown_samples)

    total_lines = sum(message_counts.values()) or 1
    return {
        "message_counts": message_counts,
        "seen_ips": seen_ips,
        "failed_by_ip": failed_attempts_by_ip,
        "failed_by_user": failed_attempts_by_user,
        "accepted_by_ip": accepted_by_ip,
        "accepted_by_user": accepted_by_user,
        "invalid_user_targets": invalid_user_targets,
        "authentication_failures": authentication_failures,
        "sudo_commands": sudo_commands,
        "unknown_samples": unknown_samples,
        "total_lines": total_lines,
    }


def categorize_line(line: str, message_counts: Counter[str], sudo_commands: List[str], unknown_samples: List[str]) -> None:
    if "Received disconnect from" in line:
        message_counts["disconnects"] += 1
    elif "Disconnected from authenticating user" in line:
        message_counts["disconnects2"] += 1
    elif "authentication failure" in line:
        message_counts["auth_failures"] += 1
    elif "Disconnected from invalid user" in line:
        message_counts["invalid_disconnects"] += 1
    elif "Disconnected from" in line:
        message_counts["disconnecteds"] += 1
    elif "Invalid user" in line:
        message_counts["invalid_users"] += 1
    elif "Connection from invalid user" in line:
        message_counts["invalid_users2"] += 1
    elif "Connection closed" in line:
        message_counts["con_closed"] += 1
    elif " session opened for user" in line:
        message_counts["sessions_opened"] += 1
    elif "Did not receive identification string from" in line:
        message_counts["no_ident_strings"] += 1
    elif "Connection reset by" in line:
        message_counts["con_resets"] += 1
    elif " maximum authentication attempts exceeded for" in line:
        message_counts["max_attempts"] += 1
    elif "check pass; user unknown" in line:
        message_counts["user_unknowns"] += 1
    elif "Failed password for invalid user" in line:
        message_counts["invalid_user_auth_failures"] += 1
    elif "Failed password for" in line:
        message_counts["failed_passwords"] += 1
    elif "session closed for user" in line:
        message_counts["sessions_closed"] += 1
    elif " Failed none for invalid user" in line:
        message_counts["failed_nones"] += 1
    elif "ignoring max retries" in line:
        message_counts["ignoring_max_retries"] += 1
    elif "Accepted password for" in line:
        message_counts["accepted_passwords"] += 1
    elif "Unable to negotiate" in line:
        message_counts["nonnegotiables"] += 1
    elif "Bad protocol version identification" in line:
        message_counts["bad_protocols"] += 1
    elif " Bad packet length" in line:
        message_counts["bad_lengths"] += 1
    elif "Refused user" in line and " for service vsftpd" in line:
        message_counts["ftp_refused"] += 1
    elif "Removed session" in line:
        message_counts["removed_sessions"] += 1
    elif " Timeout, client not responding from user" in line:
        message_counts["timeouts"] += 1
    elif "logged out. Waiting for processes to exit." in line:
        message_counts["logouts"] += 1
    elif "Failed to release session: Interrupted system call" in line:
        message_counts["failed_to_releases"] += 1
    elif ("fatal: fork of unprivileged child failed" in line or "error: fork: Cannot allocate memory" in line):
        message_counts["fatals"] += 1
    elif "New session" in line:
        message_counts["new_sessions"] += 1
    elif "primary-webserver su:" in line:
        message_counts["sus"] += 1
    elif "bad username" in line:
        message_counts["bad_users"] += 1
    elif "PAM adding faulty module" in line:
        message_counts["faulty_modules"] += 1
    elif " Authentication refused: bad ownership or modes for file" in line:
        message_counts["bad_ownerships"] += 1
    elif "delete user" in line:
        message_counts["delete_users"] += 1
    elif "removed group" in line:
        message_counts["remove_groups"] += 1
    elif "removed shadow group" in line:
        message_counts["remove_shadow_groups"] += 1
    elif "Attempted login by" in line:
        message_counts["attempted_logins"] += 1
    elif "PAM unable to dlopen" in line:
        message_counts["dlopens"] += 1
    elif (
        "Power key pressed" in line
        or "Powering Off..." in line
        or "System is powering down" in line
        or "Watching system buttons on" in line
    ):
        message_counts["system_buttons"] += 1
    elif "message authentication code incorrect" in line:
        message_counts["auth_codes"] += 1
    elif "userdel" in line:
        message_counts["delusers"] += 1
    elif "sudo:" in line:
        message_counts["misc_sudos"] += 1
        if len(sudo_commands) < SUDO_SAMPLE_LIMIT:
            sudo_commands.append(line.strip())
    elif "New seat" in line:
        message_counts["new_seats"] += 1
    elif "Server listening on" in line:
        message_counts["server_listenings"] += 1
    else:
        message_counts["unknowns"] += 1
        if len(unknown_samples) < 5:
            unknown_samples.append(line.strip())


def format_count(value: int) -> str:
    return "{:,}".format(value)


def print_top(counter: Counter[str], label: str, limit: int = 5) -> List[str]:
    result: List[str] = []
    if not counter:
        result.append(f"[REPORT] No data for {label}")
        return result
    result.append(f"[REPORT] Top {label}:")
    for i, (key, count) in enumerate(counter.most_common(limit), start=1):
        result.append(f"  {i}. {key} -> {format_count(count)} events")
    return result


def build_warnings(results: dict) -> List[str]:
    warnings: List[str] = []
    total_failed = sum(results["failed_by_ip"].values())
    total_success = sum(results["accepted_by_ip"].values())
    if total_failed > total_success * 2 and total_failed > 0:
        warnings.append("Failed SSH logins significantly outnumber successful authentications")
    for ip, count in results["failed_by_ip"].most_common():
        if count >= FAILED_THRESHOLD:
            warnings.append(f"IP {ip} generated {format_count(count)} failed logins (possible brute force)")
    if results["invalid_user_targets"]:
        hottest_user, count = results["invalid_user_targets"].most_common(1)[0]
        if count >= FAILED_THRESHOLD // 2:
            warnings.append(f"Username '{hottest_user}' was targeted {format_count(count)} times")
    message_counts = results["message_counts"]
    if message_counts["sus"]:
        warnings.append("Detected 'su' activity in logs. Verify it is expected.")
    if message_counts["delete_users"] or message_counts["delusers"]:
        warnings.append("User deletion activity observed in auth.log")
    if message_counts["bad_ownerships"]:
        warnings.append("Filesystem permission warnings detected during authentication")
    if message_counts["fatals"]:
        warnings.append("Fatal PAM or SSH errors detected")
    if message_counts["unknowns"]:
        warnings.append(f"Encountered {format_count(message_counts['unknowns'])} unclassified log lines")
    return warnings


def print_auth_report(results: dict) -> List[str]:
    lines: List[str] = []
    message_counts = results["message_counts"]
    lines.extend(
        [
            "\n#######################",
            "#### BEGIN RESULTS ####",
            "#######################\n",
            "[INFO] Summary of authentication activity",
            f"[REPORT] Successful SSH logins: {format_count(message_counts['accepted_passwords'])}",
            f"[REPORT] SSH sessions opened: {format_count(message_counts['sessions_opened'])}",
            f"[REPORT] Failed SSH logins: {format_count(message_counts['failed_passwords'])}",
            f"[REPORT] Invalid user attempts: {format_count(message_counts['invalid_users'])}",
            f"[REPORT] Authentication failures (PAM): {format_count(message_counts['auth_failures'])}",
            f"[REPORT] Timeouts: {format_count(message_counts['timeouts'])} | Disconnects: {format_count(message_counts['disconnects'])}",
            "",
            "[DETAIL] Top failed login IPs",
            *print_top(results["failed_by_ip"], "failed login IPs"),
            "",
            "[DETAIL] Top usernames targeted by attackers",
            *print_top(results["failed_by_user"], "invalid/failed usernames"),
            "",
            "[DETAIL] Successful login sources",
            *print_top(results["accepted_by_ip"], "successful login IPs"),
        ]
    )

    if results["sudo_commands"]:
        lines.append("\n[DETAIL] Sample sudo activity:")
        lines.extend(f"  {entry}" for entry in results["sudo_commands"])

    if results["unknown_samples"]:
        lines.append("\n[DETAIL] Sample unknown log entries:")
        lines.extend(f"  {entry}" for entry in results["unknown_samples"])

    warnings = build_warnings(results)
    lines.extend([
        "\n################",
        "### WARNINGS ###",
        "################",
    ])
    if warnings:
        lines.extend(f"[WARN] {warning}" for warning in warnings)
    else:
        lines.append("[INFO] No warning thresholds were triggered.")

    lines.extend(
        [
            "\n###############",
            "### IP Stats ##",
            "###############",
            f"[REPORT] Unique IPs seen: {format_count(len(results['seen_ips']))} (including successes and failures)",
            *print_top(results["seen_ips"], "overall IP chatter"),
        ]
    )
    return lines


def run_auth_bruteforce_audit(
    *, interactive: bool = True, auto_rotate_keep: int = 5
) -> Tuple[List[str], List[str], Optional[Path]]:
    master_log = prepare_master_log(VAR_LOG_DIR)
    if not master_log:
        return [], [], None
    results = analyze_auth_log(master_log)
    lines = print_auth_report(results)
    for line in lines:
        print(line)

    warnings = build_warnings(results)
    recommendations = warnings.copy()
    hot_offenders = list(results["failed_by_ip"].most_common(5))
    if hot_offenders:
        offender_ips = ", ".join(f"{ip} ({count})" for ip, count in hot_offenders)
        recommendations.append(f"Block or rate-limit repeated SSH failures from: {offender_ips}.")

    saved_path = maybe_save_log(
        lines,
        "auth-audit",
        interactive=interactive,
        auto_rotate_keep=auto_rotate_keep,
    )
    return lines, recommendations, saved_path


# ---------- database security audit ----------

@dataclass
class Finding:
    category: str
    check: str
    status: str
    details: str
    remediation: str = ""


class AuditReport:
    def __init__(self, engine: str, client_path: str) -> None:
        self.engine = engine
        self.client_path = client_path
        self.metadata: Dict[str, str] = {}
        self.findings: List[Finding] = []
        self.notes: List[str] = []

    def add_metadata(self, key: str, value: str) -> None:
        self.metadata[key] = value

    def add_finding(self, category: str, check: str, status: str, details: str, remediation: str = "") -> None:
        self.findings.append(Finding(category, check, status, details, remediation))

    def add_note(self, note: str) -> None:
        self.notes.append(note)

    def to_dict(self) -> Dict[str, object]:
        return {
            "engine": self.engine,
            "client_path": self.client_path,
            "metadata": self.metadata,
            "findings": [asdict(finding) for finding in self.findings],
            "notes": self.notes,
        }

    def render(self) -> List[str]:
        lines: List[str] = []
        header = f"Database security audit report ({self.engine})"
        lines.append("#" * len(header))
        lines.append(header)
        lines.append("#" * len(header))
        lines.append("")
        if self.metadata:
            lines.append("[Metadata]")
            for key, value in sorted(self.metadata.items()):
                lines.append(f"- {key}: {value}")
            lines.append("")
        if self.notes:
            lines.append("[Notes]")
            for note in self.notes:
                lines.append(f"- {note}")
            lines.append("")
        if not self.findings:
            lines.append("No findings were produced.")
            return lines
        lines.append("[Findings]")
        for finding in self.findings:
            lines.append(f"* ({finding.status}) [{finding.category}] {finding.check}")
            lines.append(f"    Details: {finding.details}")
            if finding.remediation:
                lines.append(f"    Remediation: {finding.remediation}")
        lines.append("")
        return lines


class CommandError(RuntimeError):
    def __init__(self, command: Sequence[str], stdout: str, stderr: str):
        self.command = list(command)
        self.stdout = stdout
        self.stderr = stderr
        super().__init__(self.__str__())

    def __str__(self) -> str:
        cmd = " ".join(self.command)
        detail = self.stderr.strip() or self.stdout.strip() or "Unknown error"
        return f"Command failed: {cmd} -> {detail}"


def run_command(command: Sequence[str], env: Optional[Dict[str, str]] = None) -> str:
    result = subprocess.run(command, capture_output=True, text=True, env=env, check=False)
    if result.returncode != 0:
        raise CommandError(command, result.stdout, result.stderr)
    return result.stdout


def detect_client(preferred: Optional[str]) -> Tuple[str, str]:
    candidates = [preferred] if preferred else ["mysql", "mariadb", "psql"]
    for candidate in candidates:
        if not candidate:
            continue
        path = shutil.which(candidate)
        if path:
            return candidate, path
    raise SystemExit("Unable to find a supported SQL client. Install mysql, mariadb or psql first.")


def detect_service_state(service_names: Iterable[str]) -> Dict[str, str]:
    states: Dict[str, str] = {}
    for name in service_names:
        state = "unknown"
        try:
            state = run_command(["systemctl", "is-active", name]).strip()
        except (FileNotFoundError, CommandError):
            try:
                output = run_command(["service", name, "status"]).splitlines()
                if output:
                    state = output[0].strip()
            except (FileNotFoundError, CommandError):
                state = "unavailable"
        states[name] = state or "unknown"
    return states


def execute_mysql_query(args: argparse.Namespace, query: str) -> List[List[str]]:
    env = os.environ.copy()
    if args.password:
        env["MYSQL_PWD"] = args.password
    command = [
        args.client_path,
        "--host",
        args.host,
        "--port",
        str(args.port),
        "--user",
        args.user,
        "--batch",
        "--raw",
        "--skip-column-names",
        "-e",
        query,
    ]
    if args.database:
        command.extend(["--database", args.database])
    output = run_command(command, env=env)
    rows = []
    for line in output.splitlines():
        line = line.rstrip("\r")
        if not line:
            continue
        rows.append(line.split("\t"))
    return rows


def execute_postgres_query(args: argparse.Namespace, query: str) -> List[List[str]]:
    env = os.environ.copy()
    if args.password:
        env["PGPASSWORD"] = args.password
    command = [
        args.client_path,
        "--host",
        args.host,
        "--port",
        str(args.port),
        "--username",
        args.user,
        "--no-psqlrc",
        "-A",
        "-t",
        query,
    ]
    if args.database:
        command.extend(["--dbname", args.database])
    output = run_command(command, env=env)
    rows = []
    for line in output.splitlines():
        line = line.rstrip("\r")
        if not line:
            continue
        rows.append(line.split("\t"))
    return rows


def gather_mysql_metadata(report: AuditReport, args: argparse.Namespace) -> None:
    try:
        version_output = run_command([args.client_path, "--version"]).strip()
        report.add_metadata("client_version", version_output)
    except CommandError as exc:
        report.add_note(str(exc))
    try:
        version_row = execute_mysql_query(args, "SELECT VERSION();")
        if version_row:
            report.add_metadata("server_version", version_row[0][0])
    except CommandError as exc:
        report.add_note(f"Could not query server version: {exc}")

    service_states = detect_service_state(["mysql", "mariadb", "mysqld"])
    report.add_metadata("service_states", json.dumps(service_states))


def gather_postgres_metadata(report: AuditReport, args: argparse.Namespace) -> None:
    try:
        version_output = run_command([args.client_path, "--version"]).strip()
        report.add_metadata("client_version", version_output)
    except CommandError as exc:
        report.add_note(str(exc))
    try:
        version_row = execute_postgres_query(args, "SELECT version();")
        if version_row:
            report.add_metadata("server_version", version_row[0][0])
    except CommandError as exc:
        report.add_note(f"Could not query server version: {exc}")

    service_states = detect_service_state(["postgresql", "postgresql@14-main", "postgres"])
    report.add_metadata("service_states", json.dumps(service_states))


def audit_mysql(report: AuditReport, args: argparse.Namespace) -> None:
    variable_names = [
        "have_ssl",
        "log_bin",
        "local_infile",
        "secure_file_priv",
        "default_password_lifetime",
        "validate_password.policy",
        "validate_password.length",
        "default_authentication_plugin",
        "sql_mode",
    ]
    try:
        placeholders = ",".join(f"'{name}'" for name in variable_names)
        rows = execute_mysql_query(args, f"SHOW GLOBAL VARIABLES WHERE Variable_name IN ({placeholders});")
        var_map = {row[0].lower(): row[1] if len(row) > 1 else "" for row in rows}
    except CommandError as exc:
        report.add_finding(
            "Configuration",
            "Global variable collection",
            "ERROR",
            str(exc),
            "Ensure the supplied credentials can run SHOW GLOBAL VARIABLES.",
        )
        var_map = {}

    def get_var(name: str) -> Optional[str]:
        return var_map.get(name.lower())

    checks = [
        ("SSL/TLS availability", "have_ssl", lambda value: value.upper() == "YES", "Enable SSL support and configure client certificates."),
        ("Binary logging", "log_bin", lambda value: value.lower() in {"on", "1"}, "Enable log_bin to support point-in-time recovery and auditing."),
        ("LOCAL INFILE disabled", "local_infile", lambda value: value == "OFF", "Set local_infile=OFF to prevent arbitrary file imports from clients."),
        ("Secure file directory", "secure_file_priv", lambda value: value not in {"", "NULL", None}, "Set secure_file_priv to a dedicated directory to limit file operations."),
        ("Password lifetime", "default_password_lifetime", lambda value: value not in {"0", "NULL", None}, "Define default_password_lifetime to force rotation of credentials."),
        ("Password validation plugin", "validate_password.policy", lambda value: value not in {"", "0", None}, "Install and configure the validate_password component."),
        ("Password minimum length", "validate_password.length", lambda value: value and int(value) >= 12, "Increase validate_password.length to at least 12 characters."),
        ("Default authentication plugin", "default_authentication_plugin", lambda value: value and "sha2" in value.lower(), "Use caching_sha2_password (MySQL 8+) or strong auth plugins."),
        ("Strict SQL mode", "sql_mode", lambda value: value and ("STRICT_ALL_TABLES" in value or "STRICT_TRANS_TABLES" in value), "Add STRICT_* modes to sql_mode to catch invalid data early."),
    ]

    for check_name, variable, evaluator, remediation in checks:
        value = get_var(variable)
        if value is None:
            report.add_finding("Configuration", check_name, "INFO", f"Variable {variable} not available")
            continue
        try:
            status = "PASS" if evaluator(value) else "FAIL"
        except Exception as exc:  # pragma: no cover
            status = "ERROR"
            value = f"{value} (evaluation error: {exc})"
        report.add_finding("Configuration", check_name, status, f"{variable}={value}", remediation)

    try:
        account_rows = execute_mysql_query(args, "SELECT user, host, plugin FROM mysql.user ORDER BY user, host;")
        auth_plugins = {row[2] for row in account_rows if len(row) >= 3 and row[2]}
        report.add_note(f"Discovered {len(account_rows)} accounts using plugins: {', '.join(sorted(auth_plugins)) or 'unknown' }.")
    except CommandError as exc:
        report.add_note(f"Could not enumerate accounts: {exc}")


def audit_postgres(report: AuditReport, args: argparse.Namespace) -> None:
    setting_names = [
        "ssl",
        "password_encryption",
        "log_connections",
        "log_disconnections",
        "log_statement",
        "log_min_error_statement",
        "log_min_duration_statement",
    ]
    unique_names = sorted(set(setting_names))
    try:
        placeholders = ",".join(f"'{name}'" for name in unique_names)
        rows = execute_postgres_query(args, f"SELECT name, setting FROM pg_settings WHERE name IN ({placeholders});")
        settings = {row[0]: row[1] for row in rows}
    except CommandError as exc:
        report.add_finding("Configuration", "Parameter collection", "ERROR", str(exc), "Ensure the supplied user can read pg_settings.")
        settings = {}

    def setting(name: str) -> Optional[str]:
        return settings.get(name)

    checks = [
        ("SSL/TLS enabled", "ssl", lambda value: value == "on", "Set ssl=on in postgresql.conf and configure certificates."),
        ("Password encryption", "password_encryption", lambda value: value == "scram-sha-256", "Use scram-sha-256 for stored passwords."),
        ("Connection logging", "log_connections", lambda value: value == "on", "Set log_connections=on to trace authentication events."),
        ("Disconnection logging", "log_disconnections", lambda value: value == "on", "Set log_disconnections=on for complete audit trails."),
        ("Statement logging", "log_statement", lambda value: value in {"ddl", "mod", "all"}, "Increase log_statement to at least 'ddl' for schema changes."),
        ("Minimum error statement logging", "log_min_error_statement", lambda value: value in {"error", "warning", "notice", "info", "debug"}, "Set log_min_error_statement=error to capture failing SQL."),
        ("Slow statement logging", "log_min_duration_statement", lambda value: value and value != "-1", "Set log_min_duration_statement to a positive value (in ms) to log slow queries."),
    ]

    for check_name, parameter, evaluator, remediation in checks:
        value = setting(parameter)
        if value is None:
            report.add_finding("Configuration", check_name, "INFO", f"Parameter {parameter} not available")
            continue
        status = "PASS" if evaluator(value) else "FAIL"
        report.add_finding("Configuration", check_name, status, f"{parameter}={value}", remediation)

    try:
        rows = execute_postgres_query(
            args,
            "SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolcanlogin FROM pg_roles ORDER BY rolname;",
        )
        superusers = [row for row in rows if len(row) >= 2 and row[1] == "t"]
        report.add_note(
            f"Discovered {len(rows)} roles ({len(superusers)} superusers). Review unnecessary superuser privileges."
        )
    except CommandError as exc:
        report.add_note(f"Could not enumerate roles: {exc}")


def summarize_database_recommendations(report: AuditReport) -> List[str]:
    recommendations: List[str] = []
    for finding in report.findings:
        if finding.status in {"FAIL", "ERROR"}:
            detail = finding.remediation or finding.details
            recommendations.append(f"{finding.check}: {detail}")
    recommendations.extend(report.notes)
    return recommendations


def run_database_audit(
    *,
    password: Optional[str] = None,
    interactive: bool = True,
    auto_rotate_keep: int = 5,
) -> Tuple[List[str], List[str], Optional[Path]]:
    client_pref = DEFAULT_DB_CLIENT
    try:
        client, client_path = detect_client(client_pref)
    except SystemExit as exc:
        print(exc)
        return [], [], None

    import argparse

    args = argparse.Namespace()
    args.client = client
    args.client_path = client_path
    args.host = DEFAULT_DB_HOST
    default_port = DEFAULT_DB_PORTS.get(client, 3306)
    args.port = int(default_port)
    args.user = DEFAULT_DB_USER.get(client, "root")
    args.password = password
    args.database = None

    if interactive and args.password is None:
        supplied = getpass.getpass("Enter database password (leave blank to try without): ").strip()
        args.password = supplied or None

    report = AuditReport(engine=client, client_path=client_path)
    report.add_metadata("host", args.host)
    report.add_metadata("port", str(args.port))
    report.add_metadata("user", args.user)

    try:
        if client in {"mysql", "mariadb"}:
            gather_mysql_metadata(report, args)
            audit_mysql(report, args)
        else:
            gather_postgres_metadata(report, args)
            audit_postgres(report, args)
    except KeyboardInterrupt:
        print("Interrupted by user")
        return [], [], None

    lines = report.render()
    for line in lines:
        print(line)
    recommendations = summarize_database_recommendations(report)

    saved_path = maybe_save_log(
        lines,
        f"{client}-audit",
        interactive=interactive,
        auto_rotate_keep=auto_rotate_keep,
    )
    return lines, recommendations, saved_path


# ---------- quick LAMP SSH checklist ----------


def ssh_prefix(target: str) -> List[str]:
    return ["ssh", target] if target else []


def run_shell(command: List[str]) -> Tuple[int, str, str]:
    result = subprocess.run(command, capture_output=True, text=True)
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def quick_lamp_checks(
    *, interactive: bool = True, auto_rotate_keep: int = 5
) -> Tuple[List[str], List[str], Optional[Path]]:
    target = DEFAULT_SSH_TARGET
    prefix = ssh_prefix(target)

    checks = {
        "Apache version": prefix + ["apache2", "-v"],
        "PHP version": prefix + ["php", "-v"],
        "MySQL/MariaDB version": prefix + ["mysql", "--version"],
        "Firewall status": prefix + ["ufw", "status"],
        "Open web/DB ports": prefix + ["sh", "-c", "ss -tuln | grep -E ':(80|443|3306)'"],
        "Fail2ban status": prefix + ["systemctl", "status", "fail2ban"],
    }

    lines: List[str] = ["[INFO] Running quick LAMP checklist" + (f" against {target}" if target else " locally")]

    for label, cmd in checks.items():
        rc, stdout, stderr = run_shell(cmd)
        lines.append(f"\n[CHECK] {label}")
        if rc == 0 and stdout:
            lines.append(stdout)
        elif rc == 0 and not stdout:
            lines.append("(no output)")
        else:
            lines.append(f"Command failed: {' '.join(cmd)}")
            if stderr:
                lines.append(stderr)

    recommendations = [
        "- Enable ufw and allow only required ports (80, 443, 22, 3306 if remote DB).",
        "- Ensure PHP and Apache versions are supported and patched.",
        "- Enable fail2ban sshd/apache filters and review jail.local thresholds.",
        "- Restrict MySQL to localhost unless remote access is required; enforce strong auth.",
        "- Consider running automatic security updates or unattended-upgrades.",
    ]
    lines.append("\n[RECOMMENDATIONS]")
    lines.extend(recommendations)

    for line in lines:
        print(line)

    saved_path = maybe_save_log(
        lines,
        "lamp-ssh-check",
        interactive=interactive,
        auto_rotate_keep=auto_rotate_keep,
    )
    return lines, recommendations, saved_path


def unique_recommendations(recommendations: List[str]) -> List[str]:
    seen = set()
    unique: List[str] = []
    for recommendation in recommendations:
        cleaned = recommendation.strip()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        unique.append(cleaned)
    return unique


def run_all_checks(auto_rotate_keep: int = 5) -> None:
    print("[INFO] Running all checks with defaults. Only database authentication will prompt if needed.\n")

    all_recommendations: List[str] = []

    _, recs, _ = run_apache_log_audit(interactive=False, auto_rotate_keep=auto_rotate_keep)
    all_recommendations.extend(recs)

    _, recs, _ = run_auth_bruteforce_audit(interactive=False, auto_rotate_keep=auto_rotate_keep)
    all_recommendations.extend(recs)

    db_password = getpass.getpass("Database password for SQL audit (leave blank to try without): ").strip()
    _, recs, _ = run_database_audit(
        password=db_password or None,
        interactive=False,
        auto_rotate_keep=auto_rotate_keep,
    )
    all_recommendations.extend(recs)

    _, recs, _ = quick_lamp_checks(interactive=False, auto_rotate_keep=auto_rotate_keep)
    all_recommendations.extend(recs)

    distilled = unique_recommendations(all_recommendations)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    rec_path = LOG_DIR / f"recommendations-{timestamp}.txt"
    if distilled:
        rec_path.write_text("\n".join(distilled) + "\n", encoding="utf-8")
    else:
        rec_path.write_text("No outstanding recommendations detected.\n", encoding="utf-8")
    print(f"\n[INFO] Saved consolidated recommendations to {rec_path}")


# ---------- interactive menu ----------

MENU_OPTIONS = {
    "0": ("Run all checks (non-interactive)", lambda: run_all_checks()),
    "1": ("Apache access/error log audit", run_apache_log_audit),
    "2": ("auth.log brute-force audit", run_auth_bruteforce_audit),
    "3": ("Database security audit (MySQL/MariaDB/PostgreSQL)", run_database_audit),
    "4": ("Quick LAMP checklist over SSH/local", quick_lamp_checks),
    "q": ("Quit", None),
}


def print_banner() -> None:
    print("#############################")
    print("#    Bodnar Security Tool    #")
    print("#  LAMP & log security aide  #")
    print("#############################\n")


def main() -> None:
    print_banner()
    while True:
        print("Available checks:")
        for key, (label, _) in MENU_OPTIONS.items():
            print(f"  {key}. {label}")
        choice = input("Select an option: ").strip().lower()
        if choice == "q":
            print("[EXIT] Goodbye.")
            return
        if choice not in MENU_OPTIONS:
            print("[WARN] Invalid choice. Please try again.\n")
            continue
        label, action = MENU_OPTIONS[choice]
        print(f"\n[INFO] Running: {label}\n")
        try:
            if action:
                action()
        except KeyboardInterrupt:
            print("\n[WARN] Check interrupted by user.")
        print("\n[INFO] Returning to main menu.\n")


if __name__ == "__main__":
    main()
