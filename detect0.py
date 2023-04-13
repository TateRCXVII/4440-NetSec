#!/usr/bin/python3

# --------------------------------------------------------
# TODO: implement your attack/defense code in this file!
# --------------------------------------------------------

import re
from scapy.all import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


# reads network traffic data from a given packet capture file 
# and extracts the relevant data to track login attempts and 
# failures made from different IP addresses.
# @param packet: the packet to parse
# @param fails: a dictionary of IP addresses to the number of failed login attempts
# @param attempts: a dictionary of IP addresses to the number of login attempts

def parsePacket(packet, fails, attempts):
    # checks if the packet contains a "TCP" layer, then extracts the payload data 
    # from the "TCP" layer and decode it to a string using utf-8 encoding
    if not packet.haslayer("TCP"):
        return

    data = bytes(packet["TCP"].payload).decode('utf-8', 'replace')
    ip = packet["IP"].src

    # updates the dictionaries with the relevant data
    if ("Login" in data):
        if (ip in attempts):
            attempts[ip] = attempts[ip] + 1
        else:
            attempts[ip] = 1
            fails[ip] = 0
    if ("Login incorrect" in data):
        fails[ip] = fails[ip] + 1

    return

if __name__ == "__main__":
    fails = dict()
    attempts = dict()
    for packet in rdpcap(sys.argv[1]):
        parsePacket(packet, fails, attempts)
    for ip in attempts:
        print("IP:" + str(ip) + ", REQS:" +
              str(attempts[ip]) + ", FAILS:" + str(fails[ip]))
        