# update packages and delete old files
yum upgrade -y
package-cleanup --leaves
package-cleanup --orphans

# set centos to automatically update
yum -y install yum-cron
systemctl enable yum-cron.service
