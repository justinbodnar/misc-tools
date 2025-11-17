#!/usr/bin/env python3
"""Analyze Linux auth.log files for brute-force attempts and anomalies."""

from __future__ import annotations

import gzip
import os
import re
import shutil
from collections import Counter
from pathlib import Path
from typing import Iterable

LOG_FILE = Path("/var/log/auth.log")
VAR_LOG_DIR = LOG_FILE.parent
TMP_DIR = Path("./tmp")
MASTER_LOG = TMP_DIR / "auth.log.MASTER"
FAILED_THRESHOLD = 25
SUDO_SAMPLE_LIMIT = 10

FAILED_PASSWORD_PATTERN = re.compile(
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>[0-9.]+)"
)
ACCEPTED_PASSWORD_PATTERN = re.compile(
    r"Accepted password for (?P<user>\S+) from (?P<ip>[0-9.]+)"
)
INVALID_USER_PATTERN = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>[0-9.]+)"
)
AUTH_FAILURE_PATTERN = re.compile(r"authentication failure.*rhost=(?P<ip>[0-9.]+)")


def throw_fatal_error(message: str) -> None:
    print(f"[EXIT] {message}")
    exit(1)


def prepare_tmp_dir() -> None:
    if TMP_DIR.exists():
        shutil.rmtree(TMP_DIR)
    TMP_DIR.mkdir(parents=True)


def copy_logs_into_tmp() -> list[Path]:
    sources = sorted(VAR_LOG_DIR.glob(f"{LOG_FILE.name}*"))
    if not sources:
        throw_fatal_error(f"No {LOG_FILE.name} files found in {VAR_LOG_DIR}")

    copied: list[Path] = []
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


def prepare_master_log() -> Path:
    if not LOG_FILE.exists():
        throw_fatal_error(f"{LOG_FILE} does not exist")
    prepare_tmp_dir()
    copied = copy_logs_into_tmp()
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
    sudo_commands: list[str] = []
    unknown_samples: list[str] = []

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


def categorize_line(
    line: str,
    message_counts: Counter[str],
    sudo_commands: list[str],
    unknown_samples: list[str],
) -> None:
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
    elif (
        "fatal: fork of unprivileged child failed" in line
        or "error: fork: Cannot allocate memory" in line
    ):
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


def print_top(counter: Counter[str], label: str, limit: int = 5) -> None:
    if not counter:
        print(f"[REPORT] No data for {label}")
        return
    print(f"[REPORT] Top {label}:")
    for i, (key, count) in enumerate(counter.most_common(limit), start=1):
        print(f"  {i}. {key} -> {format_count(count)} events")


def build_warnings(results: dict) -> list[str]:
    warnings: list[str] = []
    total_failed = sum(results["failed_by_ip"].values())
    total_success = sum(results["accepted_by_ip"].values())
    if total_failed > total_success * 2 and total_failed > 0:
        warnings.append(
            "Failed SSH logins significantly outnumber successful authentications"
        )
    for ip, count in results["failed_by_ip"].most_common():
        if count >= FAILED_THRESHOLD:
            warnings.append(
                f"IP {ip} generated {format_count(count)} failed logins (possible brute force)"
            )
    if results["invalid_user_targets"]:
        hottest_user, count = results["invalid_user_targets"].most_common(1)[0]
        if count >= FAILED_THRESHOLD // 2:
            warnings.append(
                f"Username '{hottest_user}' was targeted {format_count(count)} times"
            )
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
        warnings.append(
            f"Encountered {format_count(message_counts['unknowns'])} unclassified log lines"
        )
    return warnings


def print_report(results: dict) -> None:
    message_counts = results["message_counts"]
    print("\n#######################")
    print("#### BEGIN RESULTS ####")
    print("#######################\n")

    print("[INFO] Summary of authentication activity")
    print(
        f"[REPORT] Successful SSH logins: {format_count(message_counts['accepted_passwords'])}"
    )
    print(
        f"[REPORT] SSH sessions opened: {format_count(message_counts['sessions_opened'])}"
    )
    print(
        f"[REPORT] Failed SSH logins: {format_count(message_counts['failed_passwords'])}"
    )
    print(
        f"[REPORT] Invalid user attempts: {format_count(message_counts['invalid_users'])}"
    )
    print(
        f"[REPORT] Authentication failures (PAM): {format_count(message_counts['auth_failures'])}"
    )
    print(
        f"[REPORT] Timeouts: {format_count(message_counts['timeouts'])} | Disconnects: {format_count(message_counts['disconnects'])}"
    )

    print("\n[DETAIL] Top failed login IPs")
    print_top(results["failed_by_ip"], "failed login IPs")
    print("\n[DETAIL] Top usernames targeted by attackers")
    print_top(results["failed_by_user"], "invalid/failed usernames")
    print("\n[DETAIL] Successful login sources")
    print_top(results["accepted_by_ip"], "successful login IPs")

    if results["sudo_commands"]:
        print("\n[DETAIL] Sample sudo activity:")
        for entry in results["sudo_commands"]:
            print(f"  {entry}")

    if results["unknown_samples"]:
        print("\n[DETAIL] Sample unknown log entries:")
        for entry in results["unknown_samples"]:
            print(f"  {entry}")

    warnings = build_warnings(results)
    print("\n################")
    print("### WARNINGS ###")
    print("################")
    if warnings:
        for warning in warnings:
            print(f"[WARN] {warning}")
    else:
        print("[INFO] No warning thresholds were triggered.")

    print("\n###############")
    print("### IP Stats ##")
    print("###############")
    print(
        f"[REPORT] Unique IPs seen: {format_count(len(results['seen_ips']))} (including successes and failures)"
    )
    print_top(results["seen_ips"], "overall IP chatter")


def main() -> None:
    print("####################################")
    print("# Apache auth.log Bruteforce Audit #")
    print("# Enhanced actionable reporting    #")
    print("####################################\n")

    master_log = prepare_master_log()
    results = analyze_auth_log(master_log)
    print_report(results)


if __name__ == "__main__":
    main()
