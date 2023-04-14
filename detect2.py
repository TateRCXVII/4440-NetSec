#!/usr/bin/python3

import logging
import sys
from scapy.all import *

# Suppress Scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Dictionaries to store the count of SYN and SYN-ACK packets for each IP address
syn_packets = {}
synack_packets = {}

def parsePacket(packet):    
    # Check if the packet has a TCP layer
    if not packet.haslayer("TCP"):
        return

    # Retrieve the TCP and IP layers from the packet
    tcp_layer = packet["TCP"]
    ip_layer = packet["IP"]

    # Check if the TCP packet is a SYN packet (flag "S")
    if tcp_layer.flags == "S":
        # Increment the SYN packet count for the source IP address
        syn_packets[ip_layer.src] = syn_packets.get(ip_layer.src, 0) + 1
    # Check if the TCP packet is a SYN-ACK packet (flag "SA")
    elif tcp_layer.flags == "SA":
        # Increment the SYN-ACK packet count for the destination IP address
        synack_packets[ip_layer.dst] = synack_packets.get(ip_layer.dst, 0) + 1

if __name__ == "__main__":
    print('Analyzing packets...')
    # Read the pcap file and parse each packet using the parsePacket function
    for packet in rdpcap(sys.argv[1]):
        parsePacket(packet)

    # Iterate through the IP addresses in the SYN packets dictionary
    for ip, syn_count in syn_packets.items():
        # Get the SYN-ACK packet count for the current IP address (default to 0 if not found)
        synack_count = synack_packets.get(ip, 0)

        # Check if the IP address sent more than 3 times as many SYN packets as SYN-ACK packets received
        if syn_count > 3 * synack_count:
            # Print the IP address along with the number of SYN and SYN-ACK packets
            print(f'IP:{ip}, SYN:{syn_count}, SYNACK:{synack_count}')
