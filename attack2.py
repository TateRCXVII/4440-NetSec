#!/usr/bin/python3

import logging
import sys
from scapy.all import *

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def parsePacket(packet):
    if not packet.haslayer("TCP") or not packet.haslayer("Raw"):
        return

    # Return if packet doesn't use HTTP protocol or isn't a GET request
    if b'HTTP' not in packet["Raw"].load or b'GET' not in packet["Raw"].load:
        return

    # Retrieve the HTTP GET request
    request = packet["Raw"].load    
    host = request.split(b"Host: ")[1].split(b"\r\n")[0].decode()
    path = request.split(b"GET ")[1].split(b" HTTP")[0].decode()
    # Print in required format
    print("URL:" + host+path)

if __name__ == "__main__":
    for packet in rdpcap(sys.argv[1]):
        parsePacket(packet)