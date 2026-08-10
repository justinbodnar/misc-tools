#!/bin/bash
# fix-webserver.sh
# by Justin Bodnar
# November 14th, 2020

# move to the web root directory
echo "[fix-webserver.sh] Moving to /var/www/html"
cd /var/www/html/

# change ownership (You can comment this out later if needed)
echo "[fix-webserver.sh] Changing ownership to www-data"
chown -R www-data:www-data /var/www/html

# change directory permissions recursively
# Use 0750 so that only owner and group have full access, and 'other' has no read access.
echo "[fix-webserver.sh] Changing directory permissions to prevent cross-site access"
find /var/www/html -type d -exec chmod 0750 {} \;

# change file permissions recursively
# Use 0640 so that 'other' cannot read files.
echo "[fix-webserver.sh] Changing file permissions to prevent cross-site access"
find /var/www/html -type f -exec chmod 0640 {} \;

# to stop sibling directories from viewing one another on isolated websites/users
chmod 751 /var/www/html
