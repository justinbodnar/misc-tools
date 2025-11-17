# Apache log security audit
# by Justin Bodnar
# 7/12/2021

# imports
import os
import re
from collections import Counter
from typing import Dict, List

# debugging var
debugging = 1

# default log directory
log_dir = "/var/log/apache2/"

# function for ending program in a readable way
def throw_fatal_error():
    print("[EXIT] Fatal error encountered")
    exit()

# print opening
for i in range(25): print()
print("#############################")
print("# Apache Log Security Audit #")
print("# by Justin Bodnar          #")
print("# 7/12/2021                 #")
print("#############################\n")

##################################
# STEP 1                         #
# GET A WORKING COPY OF ALL LOGS #
##################################

# verify default dir exists
if not os.path.isdir(log_dir):
    print("[ERROR] " + log_dir + " doesn't exist.")
    throw_fatal_error()

# create output directory
if not os.path.isdir("./output"):
    os.system("mkdir ./output")
    print("[INFO] Creating ./output directory to work in")
elif len(os.listdir("output")) > 0:
    os.system("rm -rf output")
    os.system("mkdir ./output")
    print("[INFO] Deleting data from ./output directory")

# make a temporary directory to work in
if not os.path.isdir("./tmp"):
    os.system("mkdir ./tmp")
    print("[INFO] Creating ./tmp directory to work in")
elif len(os.listdir("tmp")) > 0:
    os.system("rm -rf tmp")
    os.system("mkdir ./tmp")
    print("[INFO] Deleting data from ./tmp directory")

# copies all files from apache logs
if len(os.listdir(log_dir)) < 1:
    print("[ERROR] " + log_dir + " has 0 files to analyze")
    throw_fatal_error()
else:
    print("[INFO] " + log_dir + " has " + str(len(os.listdir(log_dir))) + " files")
    os.system("cp " + log_dir + "* tmp/")
    print("[INFO] Copied " + str(len(os.listdir("tmp"))) + " files to ./tmp directory")

# unzip all gunzip files
print("[INFO] Beginning decompression of gunzip files. This may take some time.")
gzs = 0
for file in os.listdir("tmp"):
    if ".gz" in file:
        os.system("gunzip tmp/" + file)
        gzs += 1
print("[INFO] Decompressed " + str(gzs) + " gunzip files")

#####################################
# STEP 2                             #
# CONCATENATE FILES TOGETHER BY TAGS #
######################################

# sort all filenames into categories by tag
# use first two prefixes as tags to sort by
keys = {}
for file in os.listdir("tmp"):
    # first, lets get the category tag
    elements = file.split(".")
    # deal with short names
    if len(elements) > 2:
        key = elements[0] + "." + elements[1] + "." + elements[2]
        last_index_added = 2
    else:
        key = elements[0] + "." + elements[1]
        last_index_added = 1
    key = key.lower()
    # workaround for hacky situations
    if "access" not in key and "error" not in key and len(elements) > last_index_added + 1:
        last_index_added += 1
        key = key + "." + elements[last_index_added]
    # workaround for hacky situation
    if elements[0] == "access" and elements[1] == "log":
        key = "access.log"
    if elements[0] == "error" and elements[1] == "log":
        key = "error.log"
    # add this key if unseen
    if key not in keys:
        keys[key] = []
    # add this filename to this categories array
    keys[key] = keys[key] + [file]
print("[INFO] " + str(len(keys)) + " distinct sites were found.")

# create command to concat these files into a master file for each key
print("[INFO] Concatenating logs together. This may take some time.")
count = 0
for key in keys:
    count += 1
    command = "cat "
    for file in keys[key]:
        command = command + "tmp/" + file + " "
    command = command + " > tmp/" + key + "-MASTER"
    # run concat function
    os.system(command)
    # delete old files
    for file in keys[key]:
        os.system("rm tmp/" + file)
count = str(len(os.listdir("tmp")))
print("[INFO] " + count + " master files were created.")

#####################################
# STEP 2.5                          #
# SUMMARIZE MASTER LOG BEHAVIOR     #
#####################################


def analyze_access_log(path: str) -> Dict[str, object]:
        summary = {
                "name": os.path.basename(path),
                "total": 0,
                "status_counts": Counter(),
                "ip_counts": Counter(),
                "ip_error_counts": Counter(),
                "suspicious_paths": Counter(),
                "warnings": [],
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


access_reports: List[Dict[str, object]] = []
error_reports: List[Dict[str, object]] = []
for master_file in os.listdir("tmp"):
        path = os.path.join("tmp", master_file)
        if "access" in master_file:
                access_reports.append(analyze_access_log(path))
        elif "error" in master_file:
                error_reports.append(analyze_error_log(path))
print_behavior_report(access_reports, error_reports)

#################################
# STEP 3                        #
# RUN SCALP ON EACH MASTER FILE #
#################################
i = 0
print("[INFO] Running Scalp on all files.")
for file in os.listdir("tmp"):
    i += 1
    print("[INFO] Processing file " + str(i) + " of " + count)
    command = "python3 scalp.py --exhaustive --tough -l tmp/" + file + " -f ./default_filter.xml -o ./output --html >/dev/null"
    os.system(command)
print("[INFO] Log analysis complete")
# check if there are any results
if len(os.listdir("output")) < 1:
    print("[INFO] No evidence of hacking found by Scalp!\n")
    print("[EXITING] Success!")
    exit()
else:
    print("[INFO] " + str(len(os.listdir("output"))) + " results generated by Scalp.")
###############################
# STEP 4                      #
# CREATE HTML NAVIGATION FILE #
###############################
print("[INFO] Creating HTML navigation page ./output/index.html")
f = open("output/index.html", "w+")
f.write("""
<html>
<head>
<title>Apache Log Security Audit by Justin Bodnar</title>
</head>
<body>
<center>
<br /><h2>Results</h2><br />
<table border="0">
<tr><td>
<ul>
""")

# print HTML hyperlink
for file in os.listdir("output"):
    if file == "index.html":
        continue
    elements = file.split(".")
    title = elements[0] + "." + elements[1]
    f.write("\n<li><a href='" + file + "' target='_blank'>" + title + "</a></li>")

# print closing HTML
f.write("""
</ul>
</td></tr>
</table>
</center>
</body>
</html>""")
f.close()

# shutdown gracefully, empty tmp directory
print("[INFO] File complete. Removing temporary data.")
os.system("rm -rf tmp/*")
print("[EXIT] Program complete.")

