## 1. Automate Updates/Upgrades
Install the following:
```
sudo apt install -y unattended-upgrades
sudo dpkg-reconfigure --priority=low unattended-upgrades   # choose “Yes” when asked
```
ensure file `/etc/apt/apt.conf.d/20auto-upgrades` contains:
```
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
```

---

## 2. DNS: Prevent mail spoofing  
Add this TXT record at your DNS provider:  
```
TXT @ "v=spf1 -all"
```

---

## 3. Hide Apache version in errors & signature  

**In** `/etc/modsecurity/modsecurity.conf`  
```apache
SecServerSignature "Unknown"
```

---

## 4. Apache security‑headers config  
Place the following in `/etc/apache2/conf-available/security-headers.conf` (your working file):

```apache
# /etc/apache2/conf-available/security-headers.conf

# ─── Hide Apache version info and signature ───
ServerTokens Prod
ServerSignature Off

<IfModule security2_module>
  # ─── ModSecurity enabled for every WP-Admin URL ───
  <LocationMatch "^/wp-admin/">
    SecRuleEngine On
    SecRequestBodyAccess On
    SecResponseBodyAccess On
  </LocationMatch>
</IfModule>

<IfModule mod_security2.c>
  # ─── Disable ModSecurity for REST API & block-editor endpoints ───
  <LocationMatch "^/(wp-json/|index\.php/wp-json/)">
    SecRuleEngine Off
    SecRequestBodyAccess Off
    SecResponseBodyAccess Off
  </LocationMatch>

  # ─── Disable ModSecurity for XML-RPC endpoint ───
  <LocationMatch "^/xmlrpc\.php$">
    SecRuleEngine Off
    SecRequestBodyAccess Off
    SecResponseBodyAccess Off
  </LocationMatch>
</IfModule>

<IfModule mod_headers.c>
  # ─── Strip out the Server header entirely ───
  Header always unset Server
  Header always set Server ""

  # ─── Clickjacking protection ───
  Header always set X-Frame-Options "SAMEORIGIN"

  # ─── Stop MIME sniffing ───
  Header always set X-Content-Type-Options "nosniff"

  # ─── Control referrer information ───
  Header always set Referrer-Policy "strict-origin-when-cross-origin"

  # ─── Disable unnecessary browser features ───
  Header always set Permissions-Policy "geolocation=(), camera=(), microphone=(), payment=()"

  # ─── Remove CSP on all WP-Admin pages ───
  <LocationMatch "^/wp-admin/">
    Header always unset Content-Security-Policy
  </LocationMatch>

  # ─── Remove CSP on REST API endpoints ───
  <LocationMatch "^/(wp-json/|index\.php/wp-json/)">
    Header always unset Content-Security-Policy
  </LocationMatch>

  # ─── Remove CSP on cart & checkout pages ───
  <LocationMatch "^/(cart-2|checkout)/">
    Header always unset Content-Security-Policy
  </LocationMatch>

  # ─── Remove CSP on PayPal plugin assets ───
  <LocationMatch "^/wp-content/plugins/(pymntpl-paypal-woocommerce|woocommerce-paypal-payments)/">
    Header always unset Content-Security-Policy
  </LocationMatch>

  # ─── Content Security Policy (everything else) ───
  Header always set Content-Security-Policy "\
    default-src 'self'; \
    base-uri 'self'; \
    script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; \
    style-src 'self' 'unsafe-inline'; \
    img-src 'self' data: blob: https:; \
    font-src 'self'; \
    form-action 'self'; \
    object-src 'none'; \
    frame-src 'self' https://www.paypal.com https://www.paypalobjects.com; \
    frame-ancestors 'none'; \
    upgrade-insecure-requests;"

  # ─── HSTS: only send over HTTPS ───
  <If "%{HTTPS} == 'on'">
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
  </If>
</IfModule>
```

Enable and reload:
```bash
sudo a2enconf security-headers
sudo apachectl configtest
sudo apachectl -k graceful
```

---

## 5. Tame CPU during media uploads  
Force PHP to use GD (single‑threaded) instead of Imagick:

```bash
sudo phpdismod imagick
sudo systemctl restart apache2
php -m | grep -E 'imagick|gd'
```

---

## 6. MySQL: Stop BinLog Bloat  
Add this in `/etc/mysql/mysql.conf.d/mysqld.cnf`:  
```
binlog_expire_logs_seconds = 604800
max_binlog_size = 100M
```
