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

##################################
# STEP 1                         #
# GET A WORKING COPY OF ALL LOGS #
##################################

# verify default dir exists
if not os.path.isdir(log_dir):
	print( "[ERROR] "+log_dir+" doesn't exist." )
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
	print( "[ERROR] "+log_dir+" has 0 files to analyze" )
	throw_fatal_error()
else:
	print( "[INFO] "+log_dir+" has "+str(len(os.listdir(log_dir)))+" files" )
	os.system( "cp "+log_dir+"* tmp/")
	print( "[INFO] Copied "+str(len(os.listdir("tmp")))+" files to ./tmp directory" )

# unzip all gunzip files
print( "[INFO] Beginning decompression of gunzip files. This may take some time." )
gzs = 0
for file in os.listdir( "tmp" ):
	if ".gz" in file:
		os.system( "gunzip tmp/"+file )
		gzs += 1
print( "[INFO] Decompressed "+str(gzs)+" gunzip files" )

#####################################
# STEP 2                             #
# CONCATENATE FILES TOGETHER BY TAGS #
######################################

# sort all filenames into categories by tag
# use first two prefixes as tags to sort by
keys = {}
for file in os.listdir( "tmp" ):
	# first, lets get the category tag
	elements = file.split(".")
	# deal with short names
	if len(elements) > 2:
		key = elements[0]+"."+elements[1]+"."+elements[2]
		last_index_added = 2
	else:
		key = elements[0]+"."+elements[1]
		last_index_added = 1
	key = key.lower()
	# workaround for hacky situations
	if "access" not in key and "error" not in key and len(elements) > last_index_added+1:
		last_index_added += 1
		key = key + "." + elements[last_index_added]
	# workaround for hacky situation
	if elements[0] == "access" and elements[1] == "log":
		key = "access.log"
	if elements[0] == "error" and elements[1] == "log":
		key = "error.log"
	# add this key if unseen
	if key not in keys:
		keys[key] = []
	# add this filename to this ctaegories array
	keys[key] = keys[key] + [file]
print( "[INFO] "+str(len(keys))+" distinct sites were found." )

# create command to concat these files into a master file for each key
print( "[INFO] Concatenating logs together. This may take some time." )
count = 0
for key in keys:
	count += 1
	command = "cat "
	for file in keys[key]:
		command = command + "tmp/" + file + " "
	command = command + " > tmp/" + key +"-MASTER"
	# run concat function
	os.system( command )
	# delete old files
	for file in keys[key]:
		os.system( "rm tmp/"+file )
print( "[INFO] "+str(len(os.listdir("tmp")))+" master files were created." )

#################################
# STEP 3                        #
# RUN SCALP ON EACH MASTER FILE #
#################################
i = 0
print( "[INFO] Running Scalp on all files." )
for file in os.listdir("tmp"):
	i += 1
	if i > 4:
		break
	command = "python scalp.py -l tmp/"+file+" -f ./default_filter.xml -o ./scalp-output --html >/dev/null"
	os.system( command )
