# OCS-group-43

## ABOUT

This project is an implementation of several attacks intended to be run on a Local Area Network. Using Scapy's framework, it performs ARP poisoning, DNS spoofing and SSL stripping, being partially based on Ettercap's implementation.

## TESTING ENVIRONMENT

How to setup a simple virtual network for testing (router + 2 hosts (victim, attacker)):

1. Download VMware
2. Download Kali .iso for the attacker (link: https://www.kali.org/get-kali/#kali-installer-images)
3. Optionally download ubuntu .iso for victim (link: https://ubuntu.com/download/desktop), can also use kali
4. Download pfsense .iso for the router (link: https://www.pfsense.org/download/), extract the file using a tool like 7-zip
5. Open VMware, create a new virtual network via Edit > virtual network editor > add network. Make the network host-only and disable dhcpp.
6. Create attacker VM and victim VM, make sure to set their network adapter to the created virtual network (can be edited on the left while viewing the powered-off VM)
7. For the router, give it two network adapters: one for the created virtual network and the other for NAT.
8. Configure the router by assigning em0 to LAN and em1 to WAN.

After this the network should work, you can check by pinging other hosts or viewing arp tables by typing arp -n

## REQUIREMENTS

### Python

- Python 3.11+
- scapy >= 2.6.1
- psutil >= 7.2.1

### OS

The tool was developed on the latest Kali Linux version (2025.4).

It runs on any Linux-based operating system with netfilter support and `iptables` available. It is expected to be run with root privileges.

## FEATURES

### Network discovery

The tool includes functionalities to discover devices on the local network. It includes a fully automatic discovery process, and an option to let the user choose the network interface and victim devices from a list, or even a fully user configured version which skips the whole scanning process.

### ARP Poisoning

The main feature of the project is an ARP MITM attack, which poisons the ARP caches of the selected devices in order to redirect traffic to our device. The poisoning process is customizable based on the needs of the user.

In MITM mode, the packets received will be forwarded to the destination. The user of this tool can then use further programs to analyze the traffic, such as Wireshark.

There is also a DoS mode, which drops all packets that we receive from the victims.

### DNS Spoofing

Based on the user's configuration, the tool can perform DNS spoofing. Upon receiving a DNS query to a domain from the user's list, the tool drops this packet, and forges a response to it with the fake IP given by the user.

### SSL Stripping

It includes an option to use SSL stripping, which downgrades HTTPS connections of the victim to HTTP in order to read sensitive data.

## CONFIGURATION

The tool can be configured using the `config.toml` file, which includes options to customize each phase of the attack.

### Discovery

- `automatic_discovery` `(bool)`
  Enables or disables automatic device discovery during the discovery phase. During automatic discovery the tool chooses the default interface, and assigns the device whose IP matches the default gateway to group 2, while all other devices get assigned to group 1. The user can fall back to manual device selection.
- `skip_discovery` `(bool)`
  Enables or disables skipping the discovery. When enabled, it uses the hardcoded values below. The tool doesn't perform any verifying on the given hardcoded values, therefore it is the responsibility of the user to enter them correctly.
- `hardcoded_group1` `(List(Pair(str)))`
  Contains the list of victim devices in group 1. A device is represented by an IPv4 address and MAC address pair.
- `hardcoded_group2` `(List(Pair(str)))`
  Contains the list of victim devices in group 2. A device is represented by an IPv4 address and MAC address pair.
- `hardcoded_interface` `(str)`
  Contains the name of the network interface on which the attack will take place.

### ARP Poisoning

- `poison_warm_up` `(int)`
  Sets the delay between first 5 batches of forged poison packets.
- `poison_delay` `(int)`
  Sets the default delay between each batch of forged poison packets.
- `poison_icmp` `(bool)`
  Enables or disables sending forged ICMP echo requests during the poisoning process.
- `poison_reply` `(bool)`
  Enables or disables sending forged ARP replies during the poisoning process.
- `poison_request` `(bool)`
  Enables or disables sending forged ARP requests during the poisoning process.
- `poison_oneway` `(bool)`
  Enables or disables one-way poisoning. If enabled, only the ARP caches of devices in group 1 will get poisoned.
- `dos_enabled` `(bool)`
  Enables or disables DoS mode. In DoS mode all packets sent from the devices to the attacker get dropped. If disabled, all packets will get forwarded to their destination.

### DNS Spoofing

- `enabled` `(bool)`
  Enables or disables DNS spoofing. When enabled, it intercepts DNS queries from the victims, and forges responses to them if the domain is present in the list below.
- `domains` `(List(Pair(str)))`
  Contains the list of domains to be DNS spoofed. Each entry should contain a pair of the domain name and the fake IP which the victim should be redirected to.

## HOW TO RUN

The tool should be run with python with root privileges using the command `sudo python main.py`.
