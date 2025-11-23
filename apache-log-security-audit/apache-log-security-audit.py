# Apache log security audit
# by Justin Bodnar
# 7/12/2021

import argparse
import builtins
import json
import os
import re
import shutil
import gzip
import xml.etree.ElementTree as ET
from collections import Counter
from typing import Dict, List, Optional, Sequence
from urllib.request import urlopen

# debugging var
debugging = 1

# default log directory
log_dir = "/var/log/apache2/"

VERBOSITY_LEVELS = {"quiet": 0, "error": 0, "info": 1, "debug": 2}


def setup_logging(verbosity: int) -> None:
        """Monkey-patch the global print to honor verbosity flags."""

        original_print = builtins.print

        def controlled_print(*args, level: str = "info", **kwargs):
                if verbosity >= VERBOSITY_LEVELS.get(level, 1):
                        original_print(*args, **kwargs)

        builtins.print = controlled_print


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
        parser = argparse.ArgumentParser(description="Apache Log Security Audit")
        parser.add_argument(
                "--verbose",
                "-v",
                action="count",
                default=0,
                help="Increase output verbosity (use -vv for debug level).",
        )
        parser.add_argument(
                "--quiet",
                "-q",
                action="count",
                default=0,
                help="Reduce output verbosity (can silence info logs).",
        )
        parser.add_argument(
                "--filter-file",
                "-f",
                default="./default_filter.xml",
                help="XML filter definition to use when scanning master logs.",
        )
        parser.add_argument(
                "--min-impact",
                type=int,
                default=1,
                help="Only evaluate filters with at least this impact score.",
        )
        parser.add_argument(
                "--max-matches-per-rule",
                type=int,
                default=50,
                help="Cap the number of stored matches per rule per file to avoid noise.",
        )
        parser.add_argument(
                "--log-dir",
                default=log_dir,
                help="Apache log directory to audit (default: /var/log/apache2/).",
        )
        return parser.parse_args(argv)


# function for ending program in a readable way
def throw_fatal_error():
    print("[EXIT] Fatal error encountered", level="error")
    exit()


def load_filter_rules(filter_file: str, min_impact: int) -> List[Dict[str, object]]:
        if not os.path.exists(filter_file):
                print(f"[WARN] Filter file {filter_file} not found; skipping signature scan.")
                return []

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


def scan_log_file(
        log_path: str,
        rules: List[Dict[str, object]],
        max_matches_per_rule: int,
) -> List[Dict[str, object]]:
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


def write_scan_results(
        log_name: str, findings: List[Dict[str, object]], output_dir: str
) -> Optional[str]:
        if not findings:
                return None
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, f"{log_name}_findings.txt")
        with open(output_path, "w", encoding="utf-8") as handle:
                handle.write(
                        "Potentially malicious patterns identified in {0}\n".format(log_name)
                )
                handle.write("=" * 80 + "\n\n")
                for finding in findings:
                        tags = ",".join(finding.get("tags", []))
                        handle.write(
                                f"[{finding['rule_id']}] impact={finding['impact']} tags=[{tags}]\n"
                        )
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
        errors = sum(count for status, count in summary["status_counts"].items() if status.startswith("4") or status.startswith("5"))
        if summary["total"]:
                summary["error_rate"] = (errors / float(summary["total"])) * 100
        else:
                summary["error_rate"] = 0.0
        for ip, value in summary["ip_error_counts"].most_common():
                if value >= 50:
                        summary["warnings"].append(
                                f"IP {ip} generated {value} 4xx/5xx responses"
                        )
                        summary["offenders"].append(
                                {
                                        "ip": ip,
                                        "reason": f"generated {value} HTTP errors",
                                        "error_count": value,
                                }
                        )
        for keyword, hits in summary["suspicious_paths"].most_common():
                if hits > 0:
                        summary["warnings"].append(
                                f"Observed {hits} requests for suspicious path '{keyword}'"
                        )
        if summary["error_rate"] > 10:
                summary["warnings"].append(
                        f"High HTTP error rate ({summary['error_rate']:.2f}%)"
                )
        return summary


def lookup_ip_location(ip: str, cache: Dict[str, Optional[str]]) -> Optional[str]:
        if ip in cache:
                return cache[ip]
        try:
                with urlopen(f"https://ipinfo.io/{ip}/json", timeout=3) as response:
                        data = json.load(response)
                parts = [data.get("city"), data.get("region"), data.get("country")]
                location = ", ".join(part for part in parts if part)
        except Exception:
                location = None
        cache[ip] = location
        return location


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
                        summary["warnings"].append(
                                f"{count} occurrences of {key.replace('_', ' ')}"
                        )
        return summary


def print_behavior_report(access_reports: List[Dict[str, object]], error_reports: List[Dict[str, object]]) -> None:
        if not access_reports and not error_reports:
                print("[INFO] No additional behavior summaries available.")
                return
        print("\n####################################")
        print("# HTTP log behavior summary report #")
        print("####################################")
        for report in access_reports:
                print(
                        f"[REPORT][{report['name']}] {report['total']} requests | Error rate: {report['error_rate']:.2f}%"
                )
                top_ips = ", ".join(
                        f"{ip} ({count})" for ip, count in report["ip_counts"].most_common(3)
                )
                if top_ips:
                        print(f"   Top talkers: {top_ips}")
                if report["warnings"]:
                        for warning in report["warnings"]:
                                print(f"   [WARN] {warning}")
        for report in error_reports:
                print(f"[REPORT][{report['name']}] Error breakdown: {dict(report['counts'])}")
                if report["warnings"]:
                        for warning in report["warnings"]:
                                print(f"   [WARN] {warning}")


def collect_offenders(access_reports: List[Dict[str, object]]) -> List[Dict[str, object]]:
        offenders: Dict[str, Dict[str, object]] = {}
        for report in access_reports:
                for offender in report.get("offenders", []):
                        ip = offender["ip"]
                        if ip not in offenders or offender.get("error_count", 0) > offenders[ip].get(
                                "error_count", 0
                        ):
                                offenders[ip] = offender
        return list(offenders.values())


def print_enforcement_guidance(offenders: List[Dict[str, object]]) -> None:
        if not offenders:
            print("\n[ACTION] No offending IPs crossed the alert threshold.")
            return
        cache: Dict[str, Optional[str]] = {}
        print("\n########################################")
        print("# Recommended response for bad actors   #")
        print("########################################")
        print("[ACTION] The following IPs generated excessive HTTP errors:")
        for offender in offenders:
                ip = offender["ip"]
                location = lookup_ip_location(ip, cache)
                location_info = f" ({location})" if location else ""
                print(f" - {ip}{location_info}: {offender['reason']}")
        ips = ", ".join(offender["ip"] for offender in offenders)
        print("\n[ACTION] Quick block examples:")
        print("   sudo ufw deny from <IP> to any    # e.g., sudo ufw deny from 1.2.3.4")
        print("   sudo iptables -I INPUT -s <IP> -j DROP")
        print("   sudo ipset add blocked_ips <IP>   # if using ipset")
        print("Replace <IP> with any of the following:")
        print(f"   {ips}")


def concatenate_logs(tmp_dir: str) -> str:
        keys = {}
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
                master_path = os.path.join(tmp_dir, f"{key}-MASTER")
                with open(master_path, "wb") as destination:
                        for file in file_list:
                                with open(os.path.join(tmp_dir, file), "rb") as source:
                                        shutil.copyfileobj(source, destination)
                                os.remove(os.path.join(tmp_dir, file))
        total_masters = len(os.listdir(tmp_dir))
        print(f"[INFO] {total_masters} master files were created.")
        return total_masters


def main(argv: Optional[Sequence[str]] = None) -> None:
        args = parse_args(argv)
        verbosity = max(0, min(2, 1 + args.verbose - args.quiet))
        setup_logging(verbosity)

        for _ in range(3):
                print()
        print("#############################")
        print("# Apache Log Security Audit #")
        print("# by Justin Bodnar          #")
        print("# Updated with inline scalp #")
        print("#############################\n")

        working_log_dir = args.log_dir
        if not os.path.isdir(working_log_dir):
                print(f"[ERROR] {working_log_dir} doesn't exist.")
                throw_fatal_error()

        if os.path.isdir("./output"):
                shutil.rmtree("./output")
        os.makedirs("./output", exist_ok=True)
        print("[INFO] Using ./output directory for results")

        if os.path.isdir("./tmp"):
                shutil.rmtree("./tmp")
        os.makedirs("./tmp", exist_ok=True)
        print("[INFO] Using ./tmp directory as workspace")

        source_files = [f for f in os.listdir(working_log_dir) if os.path.isfile(os.path.join(working_log_dir, f))]
        if not source_files:
                print(f"[ERROR] {working_log_dir} has 0 files to analyze")
                throw_fatal_error()
        for filename in source_files:
                shutil.copy2(os.path.join(working_log_dir, filename), os.path.join("tmp", filename))
        print(f"[INFO] Copied {len(os.listdir('tmp'))} files to ./tmp directory")

        gzs = 0
        for filename in list(os.listdir("tmp")):
                if filename.endswith(".gz"):
                        gz_path = os.path.join("tmp", filename)
                        target_path = os.path.join("tmp", filename[:-3])
                        with gzip.open(gz_path, "rb") as gz_handle, open(target_path, "wb") as out:
                                shutil.copyfileobj(gz_handle, out)
                        os.remove(gz_path)
                        gzs += 1
        print(f"[INFO] Decompressed {gzs} gunzip files")

        count = concatenate_logs("tmp")

        access_reports: List[Dict[str, object]] = []
        error_reports: List[Dict[str, object]] = []
        for master_file in os.listdir("tmp"):
                path = os.path.join("tmp", master_file)
                if "access" in master_file:
                        access_reports.append(analyze_access_log(path))
                elif "error" in master_file:
                        error_reports.append(analyze_error_log(path))
        print_behavior_report(access_reports, error_reports)
        offenders = collect_offenders(access_reports)
        print_enforcement_guidance(offenders)

        print("[INFO] Running signature search on master files.")
        rules = load_filter_rules(args.filter_file, args.min_impact)
        findings_summary = []
        for index, master_file in enumerate(os.listdir("tmp"), start=1):
                print(f"[INFO] Processing file {index} of {count}: {master_file}")
                path = os.path.join("tmp", master_file)
                findings = scan_log_file(path, rules, args.max_matches_per_rule)
                output_path = write_scan_results(master_file, findings, "output")
                if output_path:
                        findings_summary.append((master_file, len(findings), output_path))

        if not findings_summary:
                print("[INFO] No evidence of hacking patterns found in master files.\n")
                print("[EXITING] Success!")
        else:
                print(f"[INFO] {len(findings_summary)} files contained suspicious patterns:")
                for item in findings_summary:
                        print(f" - {item[0]}: {item[1]} matches -> {item[2]}")

        shutil.rmtree("./tmp")
        print("[EXIT] Program complete. Temporary data removed.")


if __name__ == "__main__":
        main()

