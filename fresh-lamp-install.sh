# fresh LAMP install script
# by Justin Bodnar
# June 17, 2021

# check for new distro
apt-get update
apt-get dist-upgrade

# check for lib updates/upgrades
apt-get update
apt-get -y upgrade
apt-get autoremove
apt-get autoclean

# install apache
apt-get install apache2

# install and configure mysql server
apt-get install mysql-server
mysql_secure_installation

# install PHP
apt-get install php libapache2-mod-php php-mysql

# install certbot for free SSL
apt-get install certbot python3-certbot-apache
