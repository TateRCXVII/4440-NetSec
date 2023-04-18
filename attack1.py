#!/usr/bin/python3

import logging
import sys
import re
import base64
from scapy.all import *
from collections import defaultdict

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def parsePacket(packet):
    if not packet.haslayer("TCP") or not packet.haslayer("Raw"):
        return

    # Return if packet doesn't use HTTP protocol or isn't a GET request
    if b'HTTP' not in packet["Raw"].load or b'GET' not in packet["Raw"].load:
        return

    cred = packet["Raw"].load.split(b'Authorization: Basic ')[1].split(b'\r\n')[0]
    cred_decoded = base64.b64decode(cred).decode()
    username = cred_decoded.split(':')[0]
    password = cred_decoded.split(':')[1]
    print("USERNAME:" + username + ", PASSWORD:" + password)
    
if __name__ == "__main__":
    for packet in rdpcap(sys.argv[1]):
        parsePacket(packet)