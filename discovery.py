from scapy.all import *

ans, unans = arping("192.168.1.0/24")
ans.summary()
