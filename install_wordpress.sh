# install_wordpress.sh
# by: Justin Bodnar
# 2/6/2023
# a script to install a fresh wordpress install. to be run in the home directory

# just in case
apt install wget unzip
yum install wget unzip

# hide directory
touch index.php

# get wordpress zip
wget wordpress.org/latest.zip
unzip latest.zip
rm latest.zip

# change ownership
chown -R www-data:www-data ./

# change directory permissions recursively
find -type d -exec chmod 0755 {} \;

# change file permissions recursively
find -type f -exec chmod 0644 {} \;
