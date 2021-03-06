#!/usr/bin/python

from scapy.all import *

def print_pkt(pkt):
	if pkt[TCP] is not None:
		print("TCP Packet=====")
		print(f"\tSource: {pkt[IP].src}")
		print(f"\tDestination: {pkt[IP].dst}")
		print(f"\tTCP Source port: {pkt[TCP].sport}")
		print(f"\tTCP Destination port: {pkt[TCP].dport}")


interfaces = ['br-e12cb9117793','enp0s3','lo']
pkt = sniff(iface=interfaces, filter='tcp port 23 and src host 10.0.2.4', prn=print_pkt)