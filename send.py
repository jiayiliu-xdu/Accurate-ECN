#!/usr/bin/env python3

import argparse
import sys
import socket
import random
import struct

from scapy.all import *
from INT import Int

from time import sleep


def get_if():
    ifs = get_if_list()
    iface = None #
    for i in get_if_list():
        if "eth0" in i:
            iface = i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def main():

    if len(sys.argv)<4:
        print('pass 2 arguments: <destination> "<message>" <duration>')
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])      # Get the IP address from the domain name
    iface = get_if()                              # Getting the interface name

    pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") / IP(dst=addr,  tos=1)/TCP(dport=4321, sport=1234)
    pkt = pkt /sys.argv[2]
    pkt.show2()
    #hexdump(pkt)
    try:
      for i in range(int(sys.argv[3])):
        sendp(pkt, iface=iface)
        sleep(1)
    except KeyboardInterrupt:
        raise


if __name__ == '__main__':
    main()


