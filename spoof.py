#!/usr/bin/python
from scapy.all import *

print("sniffing packets..")

def print_pkt(pkt):
	if ICMP in pkt and pkt[ICMP].type == 8:
		print("Original Packet..")
		print("Source UP:", pkt[IP].src)
		print("Destination IP:", pkt[IP].dst)
		
		ip = IP(src=pkt[IP].dst, dst=pkt[IP].src, ihl=pkt[IP].ihl)
		icmp=ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)
		data=pkt[Raw].load
		newpkt=ip/icmp/data

		print("Spoofed Packet..")
		print("Source UP:", newpkt[IP].src)
		print("Destination IP:", newpkt[IP].dst)
		send(newpkt,verbose=0)

pkt = sniff(filter='icmp and src host 10.0.2.7',prn=print_pkt)
