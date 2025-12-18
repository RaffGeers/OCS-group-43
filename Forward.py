from scapy.all import *
import subprocess


def intercept_pkts(src_ip, dst_ip, self_mac, interface, lfilter, callback):
	sniff(
		iface=interface, 
		store=False,
		prn=lambda pkt: callback(pkt, src_ip, dst_ip, interface),
		filter=f"src host {src_ip} and ether src not {self_mac}", # intercept only packets from src_ip and ignore own (replayed) packets
		lfilter=lambda pkt: lfilter(pkt)
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
