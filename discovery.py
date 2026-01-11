from scapy.all import *
import ipaddress
import psutil

# Prompts the user to choose an interface
# Displays the CIDR of the selected interface
# Displays the number of addresses to be scanned
# Performs an ARP ping with the given CIDR
# Prompts the user to select at least 2 victims
# Returns the list of victims, interface name, the IP and MAC address of this device
def start_discovery():
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

    victims = select_victims(devices)
    
    return victims, interface_name, self_ip, self_mac

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

    victims = []
    while True:
        os.system("clear")

        if len(victims) > 0:
            print("Selected victims:")
            print_devices(victims)
            print()

        if len(devices) > 0:
            print(f"Select victim {len(victims) + 1}:")
            print_devices(devices)
            print()

        if (len(victims) >= 2):
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

        victims.append(devices[selectedVictim - 1])
        devices.remove(devices[selectedVictim - 1])

    return victims

# Prints the IP and MAC addresses of the devices list
def print_devices(devices):
    for idx, (ip, mac) in enumerate(devices):
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

    return devices