# fix-webserver.sh
# by Justin Bodnar
# November 14th, 2020

#!/bin/bash

# move to the web root directory
cd /var/www/

# change ownership
chown -R www-data:www-data /var/www/html

# change directory permissions recursively
find -type d -exec chmod 0775 {} \;

# change file permissions recursively
find -type f -exec chmod 0664 {} \;
