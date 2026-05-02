#import libraries
import subprocess
from collections import defaultdict
import time

log_file=open("alert.log","a")

#Create storage
packet_count=defaultdict(int)
start_time=time.time()

print("Starting network monitoring...\n")

#start tshark
process=subprocess.Popen(
	["sudo","tshark","-i","eth0", "-l","-n","-T","fields","-e","ip.src"],
	stdout=subprocess.PIPE,
	text=True
)

#Read each  packet
for line in process.stdout:
	ip=line.strip()
	
	if ip:
           print("IP:",ip)
           packet_count[ip]+=1
           
           current_time=time.time()

	#check time window(),check every 5seconds
	if current_time - start_time > 5:
		print("\n--Traffic Summery---")
	
	for ip_addr,count in list(packet_count.items()):
	
		if count > 5:
			msg = f"port scan detected from{ip_addr} (packets: {count})"                    
			print(msg)
			log_file.write(msg+"\n")
		
		elif count > 3:
			msg = f"High Traffic (Possible Dos) from {ip_addr} (packets: {count})"
			print(msg)
			log_file.write(msg + "\n")
			
		else:
			print(f"Normal traffic from {ip_addr} (packets: {count})")	
			
		#Reset System
		packet_count.clear()
		start_time=current_time

