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
