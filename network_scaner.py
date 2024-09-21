#!/user/bin/env python

import scapy.all as scapy
import pprint

from sympy import false


def scan(ip):
    arp_requset = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_requset_broadcast = broadcast/arp_requset
    answered_list = scapy.srp(arp_requset_broadcast, timeout=1, verbose=false)[0]
    print("IP\t\t\tMAC ADDRESS\n------------------------------------------------------")
    for element in answered_list:
        print(element[1].psrc +"\t\t"+element[1].hwsrc)

        print("------------------------------------------------------")
scan("10.0.2.2/24")
