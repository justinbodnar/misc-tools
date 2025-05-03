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
# ─── Hide Apache version info and signature ───
ServerTokens Prod
ServerSignature Off

# ─── Silence only the two CRS rules firing false-positives on WP login/ajax ───
<IfModule security2_module>
  # raise PCRE backtrack & recursion limits for ModSecurity
  SecPcreMatchLimit           500000
  SecPcreMatchLimitRecursion  500000

  <LocationMatch "^/(wp-login\.php|wp-admin/admin-ajax\.php)">
    # Remove only the SQLi & anomaly-score rules misfiring on your pwd field
    SecRuleRemoveById 942100 949110
  </LocationMatch>

  # ─── Disable ModSecurity multipart-boundary check on plugin install/update ───
  <LocationMatch "^/wp-admin/(plugin-install\.php|update\.php)$">
    SecRuleEngine Off
    SecRequestBodyAccess Off
    SecResponseBodyAccess Off
  </LocationMatch>

  # ─── Turn off blocking under /wp-admin (keep detection only) ───
  <LocationMatch "^/wp-admin/">
    SecRuleEngine DetectionOnly
    # (disabled because this directive isn’t recognized in your mod_security build)
    # SecRuleRemoveByFile /usr/share/modsecurity-crs/rules/RESPONSE-951-DATA-LEAKAGES-SQL.conf
  </LocationMatch>
</IfModule>

<IfModule mod_security2.c>
  # ─── Turn off ModSecurity completely for REST API & block-editor endpoints ───
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
  Header always set X-Frame-Options            "SAMEORIGIN"

  # ─── Prevent MIME sniffing ───
  Header always set X-Content-Type-Options     "nosniff"

  # ─── Control referrer information ───
  Header always set Referrer-Policy            "strict-origin-when-cross-origin"

  # ─── Disable unnecessary browser features ───
  Header always set Permissions-Policy         "geolocation=(), camera=(), microphone=(), payment=()"

  # ─── Disable CSP on WP admin & login ───
  SetEnvIf Request_URI "^/wp-login\.php"       CspOff
  SetEnvIf Request_URI "^/wp-admin(/|$)"       CspOff
  SetEnvIf Query_String "redirect_to="         CspOff
  SetEnvIf Query_String "reauth=1"             CspOff

  # ─── Disable CSP on REST API endpoints ───
  SetEnvIf Request_URI "^/wp-json/"            CspOff
  Header always unset Content-Security-Policy  env=CspOff

  # ─── Content Security Policy (all other URLs) ───
  Header always set Content-Security-Policy    "\
    default-src 'self'; \
    base-uri    'self'; \
    script-src  'self' 'unsafe-inline' 'unsafe-eval'; \
    style-src   'self' 'unsafe-inline'; \
    img-src     'self' data: https:; \
    font-src    'self'; \
    form-action 'self'; \
    object-src  'none'; \
    frame-ancestors 'none'; \
    upgrade-insecure-requests;"            env=!CspOff

  # ── HSTS: only send over HTTPS ──
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
