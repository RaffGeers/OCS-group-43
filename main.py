import os

def main():
    from discovery import start_discovery
    while True:
        os.system("clear")
        print("1: Start ARP poisoning attack")
        print("2: Quit")

        print()
        choice = input("Press a number: ")

        if choice == "1":
            victims = start_discovery()
        elif choice == "2":
            break

if __name__ == "__main__":
    main()