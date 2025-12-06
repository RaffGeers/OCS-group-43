from scapy.all import *
import ipaddress
import psutil

# Prompts the user to choose an interface
# Displays the CIDR of the selected interface
# Displays the number of addresses to be scanned
# Performs an ARP ping with the given CIDR
# Prompts the user to select at least 2 victims
# Returns the list of victims
def start_discovery():
    interface_name = select_interface()
    os.system("clear")
    print(f"Selected interface: {interface_name}")
    cidr = get_cidr(interface_name)
    print(f"The CIDR of the selected interface is: {cidr}")
    scan_count = ip_count(cidr)
    print(f"The program will scan {scan_count} IP addresses on the selected network")

    print()
    input("Press Enter to continue...")
    print()

    ans, unans = arping(cidr)

    victims = select_victims(ans)
    if len(victims) != 0:
        os.system("clear")
        print("selected victims:")
        print_devices(victims)
        print()
        input("Press Enter to continue...")
    
    return victims

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
def select_victims(ans):
    n_devices = len(ans)

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

        print(f"Select victim {len(victims) + 1}:")
        print_devices(ans)

        if (len(victims) >= 2):
            print()
            print("Enter D if you're done with selection")

        print()
        choice = input("Enter choice: ")

        if choice == "d":
            break

        if not choice.isdigit():
            continue
        
        selectedVictim = int(choice)

        if selectedVictim < 1 or selectedVictim > len(ans):
            continue

        victims.append(ans[selectedVictim - 1])
        ans.remove(ans[selectedVictim - 1])

    return victims

# Prints the IP and MAC addresses of the devices scanned by an ARP ping given by [ans]
def print_devices(ans):
    for idx, (s, r) in enumerate(ans):
        print(f"{idx + 1}: {r.psrc} {r.hwsrc}")

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