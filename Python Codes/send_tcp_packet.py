from scapy.all import *  
  
ip=IP()
ip.src='10.0.2.4'  
ip.dst='216.58.198.164'

tcp=TCP()  
tcp.dport=23

send(ip/tcp) 
