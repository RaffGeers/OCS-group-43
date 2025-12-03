# OCS-group-43

How to setup a simple virtual network for testing (router + 2 hosts (victim, attacker)):

1. Download VMware
2. Download Kali .iso for the attacker (link: https://www.kali.org/get-kali/#kali-installer-images)
3. (Optionally download ubuntu .iso for victim (link: https://ubuntu.com/download/desktop), can also use kali
4. Download pfsense .iso for the router (link: https://www.pfsense.org/download/), extract the file using a tool like 7-zip
5. Open VMware, create a new virtual network via Edit > virtual network editor > add network. Make the network host-only and disable dhcpp.
6. Create attacker VM and victim VM, make sure to set their network     adapter to the created virtual network (can be edited on the left while viewing the powered-off VM)
7. For the router, give it two network adapters: one for the created virtual network and the other for NAT.
8. Configure the router by assigning em0 to LAN and em1 to WAN.

After this the network should work, you can check by pinging other hosts or viewing arp tables by typing arp -n
