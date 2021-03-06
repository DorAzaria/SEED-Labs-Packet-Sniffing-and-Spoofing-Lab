from scapy.all import *

ip=IP()
ip.dst='128.230.0.0/16'
send(ip,4)
