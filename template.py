#!/usr/bin/python3

#--------------------------------------------------------
# TODO: implement your attack/defense code in this file!
#--------------------------------------------------------

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import re

def parsePacket(packet):    
    if not packet.haslayer("TCP"): 
        return
    
    data = bytes(packet["TCP"].payload).decode('utf-8','replace')

    return

if __name__ == "__main__":
    print('hello')
    for packet in rdpcap(sys.argv[1]):
        parsePacket(packet)