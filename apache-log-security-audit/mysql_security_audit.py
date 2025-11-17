#!/usr/bin/env python3
"""MySQL/MariaDB/PostgreSQL security best-practice auditor.

This utility follows the spirit of the other Apache security scripts in this
repository.  It tries to discover whichever SQL server client (``mysql``,
``mariadb`` or ``psql``) is available locally, connect to the server using the
provided credentials and emit a human-readable best practice report.  All
commands are best-effort; if a query cannot be executed the script records the
error and keeps moving.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


@dataclass
class Finding:
    """Represents the outcome of a single audit check."""

    category: str
    check: str
    status: str
    details: str
    remediation: str = ""


class AuditReport:
    """Simple container for audit metadata and findings."""

    def __init__(self, engine: str, client_path: str) -> None:
        self.engine = engine
        self.client_path = client_path
        self.metadata: Dict[str, str] = {}
        self.findings: List[Finding] = []
        self.notes: List[str] = []

    def add_metadata(self, key: str, value: str) -> None:
        self.metadata[key] = value

    def add_finding(
        self, category: str, check: str, status: str, details: str, remediation: str = ""
    ) -> None:
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

    def print_report(self) -> None:
        header = f"Database security audit report ({self.engine})"
        print("#" * len(header))
        print(header)
        print("#" * len(header))
        print()
        if self.metadata:
            print("[Metadata]")
            for key, value in sorted(self.metadata.items()):
                print(f"- {key}: {value}")
            print()
        if self.notes:
            print("[Notes]")
            for note in self.notes:
                print(f"- {note}")
            print()
        if not self.findings:
            print("No findings were produced.")
            return
        print("[Findings]")
        for finding in self.findings:
            print(f"* ({finding.status}) [{finding.category}] {finding.check}")
            print(f"    Details: {finding.details}")
            if finding.remediation:
                print(f"    Remediation: {finding.remediation}")
        print()


class CommandError(RuntimeError):
    """Raised when a subprocess call fails."""

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
    """Executes *command* and returns stdout, raising CommandError on failure."""

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    if result.returncode != 0:
        raise CommandError(command, result.stdout, result.stderr)
    return result.stdout


def detect_client(preferred: Optional[str]) -> Tuple[str, str]:
    """Find the SQL client binary to use."""

    candidates = [preferred] if preferred else ["mysql", "mariadb", "psql"]
    for candidate in candidates:
        if not candidate:
            continue
        path = shutil.which(candidate)
        if path:
            return candidate, path
    raise SystemExit(
        "Unable to find a supported SQL client. Install mysql, mariadb or psql first."
    )


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
        "-F",
        "\t",
        "-c",
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
    gather_mysql_metadata(report, args)
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
        rows = execute_mysql_query(
            args,
            f"SHOW GLOBAL VARIABLES WHERE Variable_name IN ({placeholders});",
        )
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
        (
            "SSL/TLS availability",
            "have_ssl",
            lambda value: value.upper() == "YES",
            "Enable SSL support and configure client certificates.",
        ),
        (
            "Binary logging",
            "log_bin",
            lambda value: value.lower() in {"on", "1"},
            "Enable log_bin to support point-in-time recovery and auditing.",
        ),
        (
            "LOCAL INFILE disabled",
            "local_infile",
            lambda value: value == "OFF",
            "Set local_infile=OFF to prevent arbitrary file imports from clients.",
        ),
        (
            "Secure file directory",
            "secure_file_priv",
            lambda value: value not in {"", "NULL", None},
            "Set secure_file_priv to a dedicated directory to limit file operations.",
        ),
        (
            "Password lifetime",
            "default_password_lifetime",
            lambda value: value not in {"0", "NULL", None},
            "Define default_password_lifetime to force rotation of credentials.",
        ),
        (
            "Password validation plugin",
            "validate_password.policy",
            lambda value: value not in {"", "0", None},
            "Install and configure the validate_password component.",
        ),
        (
            "Password minimum length",
            "validate_password.length",
            lambda value: value and int(value) >= 12,
            "Increase validate_password.length to at least 12 characters.",
        ),
        (
            "Default authentication plugin",
            "default_authentication_plugin",
            lambda value: value and "sha2" in value.lower(),
            "Use caching_sha2_password (MySQL 8+) or strong auth plugins.",
        ),
        (
            "Strict SQL mode",
            "sql_mode",
            lambda value: value
            and ("STRICT_ALL_TABLES" in value or "STRICT_TRANS_TABLES" in value),
            "Add STRICT_* modes to sql_mode to catch invalid data early.",
        ),
    ]

    for check_name, variable, evaluator, remediation in checks:
        value = get_var(variable)
        if value is None:
            report.add_finding(
                "Configuration",
                check_name,
                "INFO",
                f"Variable {variable} not available",
            )
            continue
        try:
            status = "PASS" if evaluator(value) else "FAIL"
        except Exception as exc:  # pragma: no cover - defensive
            status = "ERROR"
            value = f"{value} (evaluation error: {exc})"
        report.add_finding("Configuration", check_name, status, f"{variable}={value}", remediation)

    # Account overview
    try:
        account_rows = execute_mysql_query(
            args,
            "SELECT user, host, plugin FROM mysql.user ORDER BY user, host;",
        )
        auth_plugins = {row[2] for row in account_rows if len(row) >= 3 and row[2]}
        report.add_note(
            f"Discovered {len(account_rows)} accounts using plugins: {', '.join(sorted(auth_plugins)) or 'unknown'}."
        )
    except CommandError as exc:
        report.add_note(f"Could not enumerate accounts: {exc}")


def audit_postgres(report: AuditReport, args: argparse.Namespace) -> None:
    gather_postgres_metadata(report, args)
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
        rows = execute_postgres_query(
            args,
            f"SELECT name, setting FROM pg_settings WHERE name IN ({placeholders});",
        )
        settings = {row[0]: row[1] for row in rows}
    except CommandError as exc:
        report.add_finding(
            "Configuration",
            "Parameter collection",
            "ERROR",
            str(exc),
            "Ensure the supplied user can read pg_settings.",
        )
        settings = {}

    def setting(name: str) -> Optional[str]:
        return settings.get(name)

    checks = [
        (
            "SSL/TLS enabled",
            "ssl",
            lambda value: value == "on",
            "Set ssl=on in postgresql.conf and configure certificates.",
        ),
        (
            "Password encryption",
            "password_encryption",
            lambda value: value == "scram-sha-256",
            "Use scram-sha-256 for stored passwords.",
        ),
        (
            "Connection logging",
            "log_connections",
            lambda value: value == "on",
            "Set log_connections=on to trace authentication events.",
        ),
        (
            "Disconnection logging",
            "log_disconnections",
            lambda value: value == "on",
            "Set log_disconnections=on for complete audit trails.",
        ),
        (
            "Statement logging",
            "log_statement",
            lambda value: value in {"ddl", "mod", "all"},
            "Increase log_statement to at least 'ddl' for schema changes.",
        ),
        (
            "Minimum error statement logging",
            "log_min_error_statement",
            lambda value: value in {"error", "warning", "notice", "info", "debug"},
            "Set log_min_error_statement=error to capture failing SQL.",
        ),
        (
            "Slow statement logging",
            "log_min_duration_statement",
            lambda value: value and value != "-1",
            "Set log_min_duration_statement to a positive value (in ms) to log slow queries.",
        ),
    ]

    for check_name, parameter, evaluator, remediation in checks:
        value = setting(parameter)
        if value is None:
            report.add_finding(
                "Configuration",
                check_name,
                "INFO",
                f"Parameter {parameter} not available",
            )
            continue
        status = "PASS" if evaluator(value) else "FAIL"
        report.add_finding(
            "Configuration",
            check_name,
            status,
            f"{parameter}={value}",
            remediation,
        )

    # Role overview
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


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit the local SQL server (MySQL/MariaDB/PostgreSQL) for common best practices.",
    )
    parser.add_argument(
        "--client",
        choices=["mysql", "mariadb", "psql"],
        help="Preferred SQL client to use. Detected automatically when omitted.",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Database host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, help="Database port (default: 3306 for MySQL, 5432 for PostgreSQL)")
    parser.add_argument("--user", help="Database user (default: root for MySQL, postgres for PostgreSQL)")
    parser.add_argument("--password", help="Database password (uses MYSQL_PWD/PGPASSWORD when omitted)")
    parser.add_argument("--database", help="Optional default database to connect to")
    parser.add_argument("--json", action="store_true", help="Emit the report as JSON instead of text")
    return parser.parse_args()


def main() -> None:
    args = parse_arguments()
    client, client_path = detect_client(args.client)
    args.client = client
    args.client_path = client_path

    if not args.port:
        args.port = 3306 if client in {"mysql", "mariadb"} else 5432
    if not args.user:
        args.user = "root" if client in {"mysql", "mariadb"} else "postgres"

    report = AuditReport(engine=client, client_path=client_path)
    report.add_metadata("host", args.host)
    report.add_metadata("port", str(args.port))
    report.add_metadata("user", args.user)

    try:
        if client in {"mysql", "mariadb"}:
            audit_mysql(report, args)
        else:
            audit_postgres(report, args)
    except KeyboardInterrupt:
        print("Interrupted by user", file=sys.stderr)
        raise

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        report.print_report()


if __name__ == "__main__":
    main()
