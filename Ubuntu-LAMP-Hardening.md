## 1. DNS: Prevent mail spoofing  
Add this TXT record at your DNS provider:  
```
TXT @ "v=spf1 -all"
```

---

## 2. Hide Apache version in errors & signature  

**In** `/etc/modsecurity/modsecurity.conf`  
```apache
SecServerSignature "Unknown"
```

---

## 3. Apache security‑headers config  
Place the following in `/etc/apache2/conf-available/security-headers.conf` (your working file):

```apache
# /etc/apache2/conf-available/security-headers.conf

# ─── Hide Apache version info and signature ───
ServerTokens Prod
ServerSignature Off

<IfModule security2_module>
  # ─── Disable ModSecurity entirely for every WP-Admin URL ───
  <LocationMatch "^/wp-admin/">
    SecRuleEngine Off
    SecRequestBodyAccess Off
    SecResponseBodyAccess Off
  </LocationMatch>
</IfModule>

<IfModule mod_security2.c>
  # ─── Also turn off ModSecurity for REST API & block-editor endpoints ───
  <LocationMatch "^/(wp-json/|index\.php/wp-json/)">
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

  # ─── Content Security Policy (everything else) ───
  Header always set Content-Security-Policy "\
    default-src 'self' https://www.gstatic.com https://www.google.com/recaptcha/; \
    script-src  'self' 'unsafe-inline' 'unsafe-eval' \
                https://www.google.com https://www.gstatic.com; \
    frame-src   https://www.google.com/recaptcha/; \
    connect-src 'self' https://www.google.com https://www.gstatic.com; \
    img-src     'self' data: blob: https://www.google.com/recaptcha/ https://www.gstatic.com; \
    style-src   'self' 'unsafe-inline'; \
    font-src    'self'; \
    form-action 'self'; \
    object-src  'none'; \
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

## 4. Tame CPU during media uploads  
Force PHP to use GD (single‑threaded) instead of Imagick:

```bash
sudo phpdismod imagick
sudo systemctl restart apache2
php -m | grep -E 'imagick|gd'
```
