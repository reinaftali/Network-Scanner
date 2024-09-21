#!/user/bin/env python

import scapy.all as scapy
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP / IP range.")
    (options) = parser.parse_args()
    return options

def scan(ip):
    arp_requset = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_requset_broadcast = broadcast/arp_requset
    answered_list = scapy.srp(arp_requset_broadcast, timeout=1, verbose=False)[0]

    client_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dict)
    return client_list

def print_result(result_list):
    print("IP\t\t\tMAC ADDRESS\n-----------------------------------------")
    for client in result_list:
        print(client["ip"] + "\t\t" + client["mac"])


ascii_art='''

 ____     ___ ______  __    __   ___   ____   __  _     
|    \   /  _]      ||  |__|  | /   \ |    \ |  |/ ]    
|  _  | /  [_|      ||  |  |  ||     ||  D  )|  ' /     
|  |  ||    _]_|  |_||  |  |  ||  O  ||    / |    \     
|  |  ||   [_  |  |  |  `  '  ||     ||    \ |     \    
|  |  ||     | |  |   \      / |     ||  .  \|  .  |    
|__|__||_____| |__|    \_/\_/   \___/ |__|\_||__|\_|    
                                                        
  _____   __   ____  ____     ___  ____                 
 / ___/  /  ] /    ||    \   /  _]|    \                
(   \_  /  / |  o  ||  _  | /  [_ |  D  )               
 \__  |/  /  |     ||  |  ||    _]|    /                
 /  \ /   \_ |  _  ||  |  ||   [_ |    \                
 \    \     ||  |  ||  |  ||     ||  .  \               
  \___|\____||__|__||__|__||_____||__|\_|               
                                                        

'''
print("\033[92m" + ascii_art + "\033[0m")
options = get_arguments()
scan_result = scan(options.target)
print_result(scan_result)
