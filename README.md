# Misc Tools

A collection of scripts and tools written by [Justin Bodnar](https://justinbodnar.com) to simplify server management, web development, and security tasks.

---

## `sitemap_generator.sh`

Easily generate an SEO-friendly XML sitemap for your website.

Features:
- Automatically crawls the webroot to identify HTML, PHP, and (optionally) image files.
- Recursively searches all directories to ensure comprehensive coverage.
- Prevents overwriting by creating uniquely named sitemap files (e.g., `sitemap.xml`, `sitemap_2.xml`).
- Fully configurable, with options for including image files and specifying the domain name.

Usage:
1. Save the script in your webroot directory.
2. Run the command: `./sitemap_generator.sh`
3. Enter your domain name when prompted (e.g., `example.com` or `https://example.com`).
4. Inspect sitemap.xml

---

## `fresh-lamp-install.sh`

Installs and configures a complete LAMP stack (Linux, Apache, MySQL, PHP) on a fresh Ubuntu server.

Features:
- Simplifies the initial setup of a web server environment.
- Automatically installs necessary dependencies and starts services.

Usage:
1. Run the script as a superuser: `sudo ./fresh-lamp-install.sh`

---

## `fix-webserver.sh`

Fixes Apache web server permissions by targeting the `/var/www` directory.

Features:
- Recursively updates ownership and permissions to ensure proper web server functionality.

Usage:
1. Place the script in your `/var/www` directory.
2. Run: `sudo ./fix-webserver.sh`

---

## `apache-log-security-audit/`

A tool for analyzing Apache2 logs to detect potential hacking attempts.

Features:
- Parses logs for suspicious activity and signs of intrusion.
- Provides actionable insights for securing your server.

Recommended Follow-Up:
Use ClamAV to perform a detailed scan:

```
clamscan -ir --bell --detect-structured=yes --structured-ssn-format=2 --scan-mail=yes --phishing-sigs=yes --phishing-scan-urls=yes --heuristic-alerts=yes --heuristic-scan-precedence=no --scan-pe=yes --scan-elf=yes --scan-ole2=yes --scan-pdf=yes --scan-swf=yes --scan-html=yes --scan-xmldocs=yes --scan-hwp3=yes --scan-archive=yes --alert-broken=yes --alert-broken-media=yes --alert-encrypted=yes --alert-encrypted-archive=yes --alert-encrypted-doc=yes --alert-macros=yes --alert-phishing-ssl=yes --alert-phishing-cloak=yes --alert-partition-intersection=yes

```
---

Author: Justin Bodnar  
Website: [justinbodnar.com](https://justinbodnar.com)

---
