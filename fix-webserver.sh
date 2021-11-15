# fix-webserver.sh
# by Justin Bodnar
# November 14th, 2020

#!/bin/bash

# move to the web root directory
echo "[fix-webserver.sh] Moving to /var/www/html"
cd /var/www/html/

# change ownership
echo "[fix-webserver.sh] Changing ownership to www-data"
chown -R www-data:www-data /var/www/html

# change directory permissions recursively
echo "[fix-webserver.sh] Changing directory permissions"
find -type d -exec chmod 0775 {} \;

# change file permissions recursively
echo "[fix-webserver.sh] Changing file permissions"
find -type f -exec chmod 0664 {} \;
