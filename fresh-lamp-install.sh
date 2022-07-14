# fresh LAMP install script
# by Justin Bodnar
# June 17, 2021
#
# takes a fresh Ubuntu install, and installs a LAMP server with minimal user-terminal interaction

# updates
apt dist-upgrade -y
apt update -y
apt upgrade -y
apt autoremove -y
apt autoclean -y

# install apache
apt-get install apache2 -y

# install and configure mysql server with user interaction
apt-get install mysql-server -y
mysql_secure_installation

# install PHP
apt-get install php libapache2-mod-php php-mysql -y

# install certbot for free SSL
apt-get install certbot python3-certbot-apache -y
