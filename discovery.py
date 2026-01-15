from scapy.all import *
import ipaddress
import psutil
from config import config

ip_mac_cache = {}

def start_discovery():
    if config.arp.skip_discovery:
        group1, group2, interface_name, self_ip, self_mac = hardcoded_discovery()
    else:
        group1, group2, interface_name, self_ip, self_mac = dynamic_discovery()

    os.system("clear")
    print_groups(group1, group2)
    print()
    input("Press Enter to continue...")

    return group1, group2, interface_name, self_ip, self_mac

# Returns the hardcoded victims from the config
# Returns self ip and mac based on hardcoded interface
def hardcoded_discovery():
    group1 = config.arp.hardcoded_group1
    group2 = config.arp.hardcoded_group2
    interface_name = config.arp.hardcoded_interface
    self_ip = get_self_ip(interface_name)
    self_mac = get_self_mac(interface_name)
    
    return group1, group2, interface_name, self_ip, self_mac

# Prompts the user to choose an interface
# Displays the CIDR of the selected interface
# Displays the number of addresses to be scanned
# Performs an ARP ping with the given CIDR
# Prompts the user to select at least 1 victim in both group1 and group2
# Returns the list of victims (group1 and group2), interface name, the IP and MAC address of this device
def dynamic_discovery():
    if config.arp.automatic_discovery:
        interface_name = conf.iface
    else:
        interface_name = select_interface()
    os.system("clear")
    print(f"Selected interface: {interface_name}")
    self_ip = get_self_ip(interface_name)
    self_mac = get_self_mac(interface_name)
    print(f"Your local IP address: {self_ip}, your MAC address: {self_mac}")
    cidr = get_cidr(interface_name)
    print(f"The CIDR of the selected interface is: {cidr}")
    scan_count = ip_count(cidr)
    print(f"The program will scan {scan_count} IP addresses on the selected network")

    print()
    input("Press Enter to continue...")
    print()

    ans, unans = arping(cidr)
    devices = ans_to_ip_and_mac_list(ans)

    if config.arp.automatic_discovery:
        group1, group2 = automatic_victims(devices)
        while True:
            os.system("clear")
            print_groups(group1, group2)
            print()
            print("1: Continue with the automatically chosen victims")
            print("2: Choose the victims manually")
            print()
            choice = input("Enter choice: ")
            if (choice == "1"):
                break
            elif (choice == "2"):
                group1, group2 = select_victims(devices)
                break
    else:
        group1, group2 = select_victims(devices)
    
    return group1, group2, interface_name, self_ip, self_mac

# Lets the user select the network interface on which the ARP ping will be performed
def select_interface():
    interfaces = get_if_list()

    while True:
        os.system("clear")
        for idx, interface in enumerate(interfaces):
            print(f"Interface {idx + 1}: {interface}")
        
        print()
        choice = input("Enter choice: ")

        if not choice.isdigit():
            continue
        
        selectedInterface = int(choice)

        if selectedInterface < 1 or selectedInterface > len(interfaces):
            continue

        return interfaces[selectedInterface - 1]

    return

# Lets the user select at least 2 devices as victims
# Returns the list of victims chosen
def select_victims(devices):
    n_devices = len(devices)

    os.system("clear")
    if n_devices < 2:
        print("The number of devices on the local network is not enough to perform an ARP poisoning attack")

        print()
        input("Press Enter to exit...")
        return []

    # Select group 1
    group1 = []
    while True:
        os.system("clear")

        if len(group1) > 0:
            print("Group 1:")
            print_devices(group1)
            print()

        if len(devices) > 1:
            print(f"Select victim {len(group1) + 1}:")
            print_devices(devices)
            print()
        else:
            print("Only 1 device left!")
            input("Press Enter to move onto selecting the devices of group 2...")
            break

        if (len(group1) >= 1):
            print("Enter D if you're done with selection to move onto selecting the devices of group 2")
            print()

        choice = input("Enter choice: ")

        if choice == "d":
            break

        if not choice.isdigit():
            continue
        
        selectedVictim = int(choice)

        if selectedVictim < 1 or selectedVictim > len(devices):
            continue

        group1.append(devices[selectedVictim - 1])
        devices.remove(devices[selectedVictim - 1])

    # Select group 2
    group2 = []
    while True:
        os.system("clear")

        if len(group2) > 0:
            print("Group 2:")
            print_devices(group2)
            print()

        if len(devices) > 0:
            print(f"Select victim {len(group2) + 1}:")
            print_devices(devices)
            print()

        if (len(group2) >= 1):
            print("Enter D if you're done with selection")
            print()

        choice = input("Enter choice: ")

        if choice == "d":
            break

        if not choice.isdigit():
            continue
        
        selectedVictim = int(choice)

        if selectedVictim < 1 or selectedVictim > len(devices):
            continue

        group2.append(devices[selectedVictim - 1])
        devices.remove(devices[selectedVictim - 1])

    return group1, group2

# Automatic choice is router in group 2, all other devices in group 1
def automatic_victims(devices):
    group1 = []
    group2 = []

    gateway_ip = conf.route.route("0.0.0.0")[2]
    for ip, mac in devices:
        # If the device is the gateway IP assume it's the router and add it to group 2
        if ip == gateway_ip:
            group2.append((ip, mac))
        # Add all other devices to group 1
        else:
            group1.append((ip, mac))

    return group1, group2

# Prints the IP and MAC addresses of the devices list
def print_devices(devices):
    gateway_ip = conf.route.route("0.0.0.0")[2]
    for idx, (ip, mac) in enumerate(devices):
        if ip == gateway_ip:
            print(f"{idx + 1}: {ip} {mac} (default gateway)")
        else:
            print(f"{idx + 1}: {ip} {mac}")

# Returns CIDR (e.g. 192.168.1.0/24) of the given interface
def get_cidr(interface_name):
    addrs = psutil.net_if_addrs()
    
    if interface_name not in addrs:
        return None
    
    for addr in addrs[interface_name]:
        if addr.family == socket.AF_INET: # only check IPv4
            ip = addr.address
            netmask = addr.netmask
            if ip and netmask:
                network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                return str(network)

    return None

# Returns the total number of IP addresses on the given CIDR
def ip_count(cidr):
    network = ipaddress.IPv4Network(cidr, strict=False)
    return network.num_addresses

# Returns the local IP address of this device on the given interface
def get_self_ip(interface_name):
    return get_if_addr(interface_name)

# Returns the MAC address of this device on the given interface
def get_self_mac(interface_name):
    return get_if_hwaddr(interface_name)

# Converts the ans list of an arping() to a list of IP and MAC addresses
def ans_to_ip_and_mac_list(ans):
    devices = []
    for sent, recv in ans:
        ip = recv.psrc
        mac = recv.hwsrc
        devices.append((ip, mac))
        ip_mac_cache[ip] = mac

    return devices

# Prints the device IP and MAC pairs in the 2 groups
def print_groups(group1, group2):
    print("Group 1:")
    print_devices(group1)
    print()
    print("Group 2:")
    print_devices(group2)