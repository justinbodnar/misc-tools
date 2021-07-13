# Apache log security audit
# by Justin Bodnar
# 7/12/2021

# imports
import os
import re
import os.path

# default log file
log_file = "/var/log/auth.log"

# function for ending program in a readable way
def throw_fatal_error():
	print( "[EXIT] Fatal error encountered" );
	print
	exit()

# print opening
for i in range(25): print
print( "####################################" )
print( "# Apache auth.log Bruteforce Audit #" )
print( "# by Justin Bodnar                 #" )
print( "# 7/12/2021                        #" )
print( "####################################\n" )

##################################
# STEP 1                         #
# GET A WORKING COPY OF ALL LOGS #
##################################

# verify default log exists
if not os.path.exists(log_file):
	print( "[ERROR] "+log_file+" doesn't exist." )
	throw_fatal_error()

# make a temporary directory to work in
if not os.path.isdir("./tmp"):
	os.system( "mkdir ./tmp" )
	print( "[INFO] Creating ./tmp directory to work in" )
elif len(os.listdir("tmp")) > 0:
	os.system( "rm -rf tmp" )
	os.system( "mkdir ./tmp" )
	print( "[INFO] Deleting data from ./tmp directory" )

# copies all auth.log.n files
count = 0
for filename in os.listdir( "/var/log" ):
	if "auth.log" in filename:
		count += 1
print( "[INFO] There are "+str(count)+" files" )
os.system( "cp "+log_file+"* tmp/")
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
command = "cat "
seen = []
for filename in os.listdir( "tmp" ):
	command = command + " tmp/" + filename
	seen.append( filename )
command = command + " > tmp/auth.log.MASTER"
os.system( command )
print( "[INFO] One master file created." )
# delete old files
for filename in seen:
	os.system( "rm tmp/"+filename )
print( "[INFO] Deleted temporary files." )


###############################
# STEP 3                      #
# ITERATE THROUGH MASTER FILE #
###############################

# get number of total lines to go through
num_lines = sum(1 for line in open('tmp/auth.log.MASTER'))
# calculate percentages
p1 = int(.10 * num_lines)
p2 = int(.20 * num_lines)
p3 = int(.30 * num_lines)
p4 = int(.40 * num_lines)
p5 = int(.50 * num_lines)
p6 = int(.60 * num_lines)
p7 = int(.70 * num_lines)
p8 = int(.80 * num_lines)
p9 = int(.90 * num_lines)
num_lines ="{:,}".format(num_lines)
seen_ips = {}
f = open( "tmp/auth.log.MASTER", "r" )
curr = 0
disconnects = 0
disconnects2 = 0
auth_failures = 0
invalid_users = 0
con_closed = 0
unknowns = 0
print( "[INFO] Processing file. This may take some time." )
for line in f:
	curr = curr + 1
	if curr == p1:
		print( "[ITER] 10% of "+num_lines+" lines processed." )
	elif curr == p2:
		print( "[ITER] 20% of "+num_lines+" lines processed." )
	elif curr == p3:
		print( "[ITER] 30% of "+num_lines+" lines processed." )
	elif curr == p4:
		print( "[ITER] 40% of "+num_lines+" lines processed." )
	elif curr == p5:
		print( "[ITER] 50% of "+num_lines+" lines processed." )
	elif curr == p6:
		print( "[ITER] 60% of "+num_lines+" lines processed." )
	elif curr == p7:
		print( "[ITER] 70% of "+num_lines+" lines processed." )
	elif curr == p8:
		print( "[ITER] 80% of "+num_lines+" lines processed." )
	elif curr == p9:
		print( "[ITER] 90% of "+num_lines+" lines processed." )
	################
	# look for ips #
	ips = re.findall( r'[0-9]+(?:\.[0-9]+){3}', line )
	for ip in ips:
		if ip not in seen_ips:
			seen_ips[ip] = 1
		else:
			seen_ips[ip] = seen_ips[ip] + 1
	########################
	# look for message types #
	if "Received disconnect from" in line:
		disconnects += 1
	elif "Disconnected from authenticating user" in line:
		disconnects2 += 1
	elif "authentication failure" in line:
		auth_failures += 1
	elif "Invalid user" in line:
		invalid_users += 1
	elif "Connection closed" in line:
		con_closed += 1
	else:
#		print( line )
		unknowns += 1
print( "[ITER] 100% of "+num_lines+" lines processed." )

################
# STEP 4       #
# PRINT REPORT #
################

# results header
print( "\n#######################################" )

#########################
# print message reports #
auth_failures = "{:,}".format(auth_failures)
print( "[REPORT] Auth Failures: " + auth_failures )
invalid_users = "{:,}".format(invalid_users)
print( "[REPORT] Invalid Users: " + invalid_users )
disconnects = "{:,}".format(disconnects)
print( "[REPORT] Disconnect messages type a: " + disconnects )
disconnects2 = "{:,}".format(disconnects2)
print( "[REPORT] Disconnect messages type b: " + disconnects2 )
con_closed = "{:,}".format(con_closed)
print( "[REPORT] Connection closed messages: " + con_closed )
unknowns = "{:,}".format(unknowns)
print( "[REPORT] Unknown messages: " + unknowns )

###################
# print IP report #
seen_ips = sorted(seen_ips.items(), key=lambda x:x[1])
sorted_seen_ips = []
for ip in seen_ips:
	sorted_seen_ips = [ip] + sorted_seen_ips
count ="{:,}".format(len(seen_ips))
print( "[REPORT] Unique IPs Seen: "+count )
print( "[REPORT] Top 5 IPs Seen" )
i = 0
for ip in sorted_seen_ips:
	i = i + 1
	if i > 5:
		break
	mentions ="{:,}".format(ip[1])
	print( "[REPORT] "+str(i)+": "+str(ip[0])+" with "+mentions+" mentions" )
