# Program: netcollector
# Author: Adam R Clark
# Last Edited: 29 AUG 18

# Imports
import sys
import subprocess
import time

# Exit the program if tcpdump is not installed.
try:
    subprocess.call(["tcpdump", "--version"])
except OSError as e:
    print "tcpdump is not installed. Exiting as tcpdump is required to run NETCOLLECTOR."
    sys.exit()

# Edit sys.path to include scapy import directory. Exit the program if scapy is not found.
scapy_dir = "imports/scapy-2.4.0"
scapy_dir_status = subprocess.call("test -e '{}'".format(scapy_dir), shell=True)
if scapy_dir_status == 1:
    print "scapy directory not found. Exiting as scapy is required to run NETCOLLECTOR."
    sys.exit()
sys.path.insert(0, scapy_dir)

# Import scapy
from scapy.all import *

# Clear the console screen before running.
subprocess.call(["clear"])

# Specify the interface to listen on. Default is all interfaces.
# Uncomment the line below and add iface=int to the sniff function options at the bottom of script.
# int = ["enp0s3", "lo"]
# Specify gateway address you want to be alerted to mac-spoofing for.
gateway = "192.168.0.253"

# Create empty list to store discovered hosts.
disc_hosts_l = []

# Create/touch hosts and log files.
subprocess.call(["touch", "arp_hosts"])
subprocess.call(["touch", "hosts.log"])

# Read in existing hosts data from previous runs.
with open("arp_hosts") as f:
    hosts = f.read()
    new_host = hosts.split('\n')

for h in new_host:
    # Skip empty lines.
    if h == "":
        pass
    else:
        print "Reading in host: " + h
        host = h.split(",")
        try:
            disc_host = (host[0],host[1])
            disc_hosts_l.append(disc_host)
        except:
            pass

# Function to run each time an arp packet is seen.
def pkt_callback(pkt):
    l2src = pkt.hwsrc
    l3src = pkt.psrc
    l3src_string = str(l3src)
    disc_host = (l2src,l3src)
    # Skip quad zero source addresses as we see these again once IP configuration completes.
    if l3src == "0.0.0.0":
        pass
    # Skip 169.254 APIPA addresses.
    elif "169.254" in l3src_string:
        pass
    # Alert if gayteway has a new mac-address.
    elif l3src == gateway:
        for ip in disc_hosts_l:
            if ip[1] == gateway and ip[0] != l2src:
		disc_date = (time.strftime("%d/%m/%Y"))
                disc_time = (time.strftime("%H:%M:%S"))
                print "ALERT (GW MAC CHANGE): " + disc_host[0] + "," + disc_host[1] + " DISCOVERED ON " + disc_date + " AT " + disc_time
                hosts_log_f = open("hosts.log", "a")
                hosts_log_f.write("ALERT (GW MAC CHANGE): " + disc_host[0] + "," + disc_host[1] + " DISCOVERED ON " + disc_date + " AT " +
disc_time + "\n")
    # Skip existing entries.
    elif disc_host in disc_hosts_l:
		pass
    # Add new host to log and print to console.
    else:
		disc_hosts_l.append(disc_host)
		disc_date = (time.strftime("%d/%m/%Y"))
		disc_time = (time.strftime("%H:%M:%S"))
		disc_hosts_f = open("arp_hosts", "a")
		disc_hosts_f.write(disc_host[0] + "," + disc_host[1] + "\n")
		disc_hosts_f.close()
		print "HOST: " + disc_host[0] + "," + disc_host[1] + " DISCOVERED ON " + disc_date + " AT " + disc_time
		hosts_log_f = open("hosts.log", "a")
		hosts_log_f.write("HOST: " + disc_host[0] + "," + disc_host[1] + " DISCOVERED ON " + disc_date + " AT " +
disc_time + "\n")
		hosts_log_f.close()

print "\nNETCOLLECTOR\n"

sniff(filter="arp",store=0,prn=pkt_callback)
