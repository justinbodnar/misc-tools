# Apache log security audit
# by Justin Bodnar
# 7/12/2021

# imports
import os

# debugging var
debugging = 1

# default log directory
log_dir = "/var/log/apache2/"

# function for ending program in a raadable way
def throw_fatal_error():
	print( "[EXIT] Fatal error encountered" );
	print
	exit()

# print opening
for i in range(25): print
print( "#############################" )
print( "# Apache Log Security Audit #" )
print( "# by Justin Bodnar          #" )
print( "# 7/12/2021                 #" )
print( "#############################\n" )


# verify default dir exists
if not os.path.isdir(log_dir):
	print( "[ERROR] '"+log_dir+"' doesn't exist." )
	throw_fatal_error()

# make a temporary directory to work in
if not os.path.isdir("./tmp"):
	os.system( "mkdir ./tmp" )
	print( "[INFO] Creating ./tmp directory to work in" )
elif len(os.listdir("tmp")) > 0:
	os.system( "rm -rf tmp" )
	os.system( "mkdir ./tmp" )
	print( "[INFO] Deleting data from ./tmp directory" )

# copies all files from apache logs
if len(os.listdir(log_dir)) < 1:
	print( "[ERROR] '"+log_dir+"' has 0 files to analyze" )
else:
	print( "[INFO] '"+log_dir+"' has "+str(len(os.listdir(log_dir)))+" files" )

# go through all files in log dir
#for file in os.listdir( log_dir ):
#	print( file )

# print ending newline for readability
print
