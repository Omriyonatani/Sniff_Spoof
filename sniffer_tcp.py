#!/usr/bin/python
from scapy.all import *

print("sniffing packets..")

def print_pkt(pkt):
	pkt.show()
pkt = sniff(filter='tcp and dst port 23',prn=print_pkt)
