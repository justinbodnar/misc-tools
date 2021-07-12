# Apache log security audit
# by Justin Bodnar
# 7/12/2021
import os

# default log directory
log_dir = "/var/log/apache2/"

# make a temporary directory
os.system( "mkdir ./tmp" )

# go through all files in log dir
for file in os.listdir( log_dir ):
	print( file )
