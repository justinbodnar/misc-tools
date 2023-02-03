yum upgrade -y
package-cleanup --leaves
package-cleanup --orphans
yum -y install yum-cron
