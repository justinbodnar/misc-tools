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
bad_lengths = 0
nonnegotiables = 0
removed_sessions = 0
no_ident_strings = 0
disconnects = 0
bad_protocols = 0
ftp_refused = 0
accepted_passwords = 0
sessions_opened = 0
failed_nones = 0
ignoring_max_retries = 0
disconnects2 = 0
disconnecteds = 0
max_attempts = 0
invalid_disconnects = 0
user_unknowns = 0
con_resets = 0
sessions_closed = 0
invalid_user_auth_failures = 0
failed_passwords = 0
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
	# need ups
	elif "authentication failure" in line:
		auth_failures += 1
	elif "Disconnected from invalid user" in line:
		invalid_disconnects += 1
	elif "Disconnected from" in line:
		disconnecteds += 1
	elif "Invalid user" in line:
		invalid_users += 1
	elif "Connection closed" in line:
		con_closed += 1
	# NEED USERS #
	elif " session opened for user" in line:
		sessions_opened += 1
	# need users
	elif "Did not receive identification string from" in line:
		no_ident_strings += 1
	# need users
	elif "Connection reset by" in line:
		con_resets += 1
	# need users
	elif " maximum authentication attempts exceeded for" in line:
		max_attempts += 1
	# need users
	elif "check pass; user unknown" in line:
		user_unknowns += 1
	# need users
	elif "Failed password for invalid user" in line:
		invalid_user_auth_failures += 1
	# need users
	elif "Failed password for" in line:
		failed_passwords += 1
	# need users
	elif "session closed for user" in line:
		sessions_closed += 1
	# need users
	elif " Failed none for invalid user" in line:
		failed_nones += 1
	elif "ignoring max retries" in line:
		ignoring_max_retries += 1
	# NEED USERS #
	elif "Accepted password for" in line:
		accepted_passwords += 1
	# need ips
	elif "Unable to negotiate" in line:
		nonnegotiables += 1
	# need users
	elif "Bad protocol version identification" in line:
		bad_protocols += 1
	# need sizes
	elif " Bad packet length" in line:
		bad_lengths += 1
	elif "Refused user" in line and " for service vsftpd" in line:
		ftp_refused += 1
	# need session ids
	elif "Removed session" in line:
		removed_sessions += 1
	else:
#		print( line )
		unknowns += 1
print( "[ITER] 100% of "+num_lines+" lines processed." )

################
# STEP 4       #
# PRINT REPORT #
################

# results header
print( "\n#######################" )
print( "#######################" )
print( "#### BEGIN RESULTS ####" )
print( "#######################" )
print( "#######################\n" )

#########################
# print auth reports #
print( "\n################" )
print( "# VALID LOGINS #" )
print( "################" )
sessions_opened = "{:,}".format(sessions_opened)
print( "[REPORT] SSH Sessions opened: " + sessions_opened )
accepted_passwords = "{:,}".format(accepted_passwords)
print( "[REPORT] Accepted passwords: " + accepted_passwords )

#######################
# print auth failures #
print( "\n##################" )
print( "# INVALID LOGINS #" )
print( "##################" )
auth_failures = "{:,}".format(auth_failures)
print( "[REPORT] Auth failures: " + auth_failures )
failed_passwords = "{:,}".format(failed_passwords)
print( "[REPORT] Failed passwords: " + failed_passwords )
ftp_refused = "{:,}".format(ftp_refused)
print( "[REPORT] FTP connections refused: " + ftp_refused )
invalid_users = "{:,}".format(invalid_users)
print( "[REPORT] Invalid users: " + invalid_users )
user_unknowns = "{:,}".format(user_unknowns)
print( "[REPORT] User unknown messages: " + user_unknowns )
failed_nones = "{:,}".format(failed_nones)
print( "[REPORT] Failed none from invalid user messages: " + failed_nones )
invalid_user_auth_failures = "{:,}".format(invalid_user_auth_failures)
print( "[REPORT] Invalid user auth failures: " + invalid_user_auth_failures )
max_attempts = "{:,}".format(max_attempts)
print( "[REPORT] Max num of attempts messages: " + max_attempts )
ignoring_max_retries = "{:,}".format(ignoring_max_retries)
print( "[REPORT] Ignoring max retries messages: " + ignoring_max_retries )
invalid_disconnects = "{:,}".format(invalid_disconnects)
print( "[REPORT] Invalid user disconnect messages: " + invalid_disconnects )

#######################
# print misc messages #
print( "\n#################" )
print( "# MISC MESSAGES #" )
print( "#################" )

nonnegotiables = "{:,}".format(nonnegotiables)
print( "[REPORT] Can't negotiate messages: " + nonnegotiables )
no_ident_strings = "{:,}".format(no_ident_strings)
print( "[REPORT] No identity string messages: " + no_ident_strings )
sessions_closed = "{:,}".format(sessions_closed)
print( "[REPORT] Session closed messages: " + sessions_closed )
con_resets = "{:,}".format(con_resets)
print( "[REPORT] Connection reset messages: " + con_resets )
disconnecteds = "{:,}".format(disconnecteds)
print( "[REPORT] Disconnected from messages: " + disconnecteds )
disconnects = "{:,}".format(disconnects)
print( "[REPORT] Disconnect messages type a: " + disconnects )
disconnects2 = "{:,}".format(disconnects2)
print( "[REPORT] Disconnect messages type b: " + disconnects2 )
con_closed = "{:,}".format(con_closed)
print( "[REPORT] Connection closed messages: " + con_closed )
bad_protocols = "{:,}".format(bad_protocols)
print( "[REPORT] Bad protocol messages: " + bad_protocols )
bad_lengths = "{:,}".format(bad_lengths)
print( "[REPORT] Bad length messages: " + bad_lengths )

###################
# print IP report #
print( "\n#############" )
print( "# IP Report #" )
print( "#############" )
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

##################
# print unknowns #
print( "\n###############" )
print( "# UNPROCESSED #" )
print( "###############" )
unknowns = "{:,}".format(unknowns)
print( "[REPORT] Unknown messages: " + unknowns )
print
