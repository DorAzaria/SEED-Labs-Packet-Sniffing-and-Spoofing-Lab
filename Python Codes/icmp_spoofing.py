from scapy.all import *

a = IP()
a.src = '1.2.3.4'
a.dst = '10.0.2.6'
send(a/ICMP())
ls(a)