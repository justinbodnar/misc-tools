# Misc Tools

A collection of scripts and tools written by [Justin Bodnar](https://justinbodnar.com) and tailored to my personal workflow to simplify server management, web development, and security tasks.

---

## `isolate_websites.sh`

Automates the isolation of individual websites by compartmentalizing their file systems and assigning dedicated users and groups. This containment strategy hinders adversaries from pivoting between compromised sites, effectively neutralizing lateral movement within the host. By configuring per-site PHP-FPM pools and enforcing `open_basedir` restrictions under `/var/www/html`, this script significantly reduces the attack surface and helps maintain a more secure hosting environment.


Features:
- Automatically creates a dedicated system user and group per website.
- Enforces secure file permissions and `open_basedir` restrictions.
- Configures individual PHP-FPM pools and updates corresponding Apache virtual hosts.
- Enhances security by preventing cross-site access to files.

Requirements/Caveats:
- Webroot must be `/var/www/html/`
- Websites must be in their own folders in webroot. ie.
    - `/var/www/html/myfirstwebsite.com`
    - `/var/www/html/mysecondwebsite.org`
    - `/var/www/html/staging.mythirdwebsite.net`
- Users are generated from text found before the final period. ie. the previous websites will create users
    - `myfirstwebsite`
    - `mysecondwebsite`
    - `staging.mythirdwebsite`

Usage:

`./isolate_websites.sh`

---

## `./apache-log-security-audit/`

A tool for analyzing Apache2 logs and identifying potential infiltration attempts.

**Features:**
- Parses logs to reveal suspicious activity and indicators of compromise.
- Delivers actionable intelligence for reinforcing your server’s defenses.

**Recommended Follow-Up:**
Utilize ClamAV for a comprehensive malware scan and further hardening of your environment:


```
clamscan -ir --bell --detect-structured=yes --structured-ssn-format=2 --scan-mail=yes --phishing-sigs=yes --phishing-scan-urls=yes --heuristic-alerts=yes --heuristic-scan-precedence=no --scan-pe=yes --scan-elf=yes --scan-ole2=yes --scan-pdf=yes --scan-swf=yes --scan-html=yes --scan-xmldocs=yes --scan-hwp3=yes --scan-archive=yes --alert-broken=yes --alert-broken-media=yes --alert-encrypted=yes --alert-encrypted-archive=yes --alert-encrypted-doc=yes --alert-macros=yes --alert-phishing-ssl=yes --alert-phishing-cloak=yes --alert-partition-intersection=yes

```

---
## `fix-webserver.sh`

Fixes Apache web server permissions by targeting the `/var/www` directory.

Features:
- Recursively updates ownership and permissions to ensure proper web server functionality.
- This script is NOT compatable with `isolate_websites.sh`
    -  you must modify or comment out the `chown` line to make it so

Usage:
1. Place the script in your `/var/www` directory.
2. Run: `sudo ./fix-webserver.sh`

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

Packages:
- `apache2`
- `mysql-server`
- `php`
- `libapache2-mod-php`
- `php-mysql`
- `git`
- `certbot`
- `python3`
- `python3-certbot-apache`
- `python3-pip`


Usage:

`sudo ./fresh-lamp-install.sh`

---

## `domain-mx-checker.py`

A simple Python script to audit a list of domains for email protection:

- **Checks**:
  - MX records
  - SPF records
  - DKIM records (only if MX present)
  - DMARC records
- **Input file**: `domain-mx-checker-input.txt` (one domain per line)
- **Output**:
  - Lists domains missing SPF, DKIM or DMARC
  - “Fully Protected” domain summary
  - Final action plan with DNS entries to add

### Requirements

- `python3`
- `dnspython` (install via `pip3 install dnspython`)

### Usage

```bash
# Basic run (reads from domain-mx-checker-input.txt)
python3 domain-mx-checker.py

# Verbose mode for detailed DNS lookup traces
python3 domain-mx-checker.py -v
```
---

Author: Justin Bodnar
Website: [justinbodnar.com](https://justinbodnar.com)

---
