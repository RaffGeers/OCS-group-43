from scapy.all import *
import os

while True:
    os.system("clear")
    print("1: Start ARP poisoning attack")
    print("2: Quit")

    choice = input("Press a number: ")

    if choice == "1":
        ans, unans = arping("192.168.1.0/24")

        victims = []
        while len(victims) < 2:
            os.system("clear")
            print(f"select victim {len(victims) + 1}:")
            for idx, (s, r) in enumerate(ans):
                print(f"{idx + 1}: {r.psrc} {r.hwsrc}")
            choice = input("Press a number: ")

            if not choice.isdigit():
                 continue
            
            selectedVictim = int(choice)

            if selectedVictim < 1 or selectedVictim > len(ans):
                continue

            victims.append(ans[selectedVictim - 1])
            ans.remove(ans[selectedVictim - 1])
            
        os.system("clear")
        print("selected victims:")
        for idx, (s, r) in enumerate(victims):
                print(f"{idx + 1}: {r.psrc} {r.hwsrc}")

        input("continue...")
    elif choice == "2":
        break