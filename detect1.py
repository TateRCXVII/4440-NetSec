#!/usr/bin/python3

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import sys

def parsePacket(packet):
    if not packet.haslayer("TCP"):
        return
    
    src_ip = packet["IP"].src
    tcp_flags = packet["TCP"].flags

    # Detect NULL scan
    if tcp_flags == 0:
        if src_ip not in NULL_scan_counts:
            NULL_scan_counts[src_ip] = 0
        NULL_scan_counts[src_ip] += 1

    # Detect FIN scan
    if tcp_flags == 0x01:
        if src_ip not in FIN_scan_counts:
            FIN_scan_counts[src_ip] = 0
        FIN_scan_counts[src_ip] += 1

    # Detect XMAS scan
    if tcp_flags == (0x01 | 0x08 | 0x20):  # FIN, PSH, and URG flags set
        if src_ip not in XMAS_scan_counts:
            XMAS_scan_counts[src_ip] = 0
        XMAS_scan_counts[src_ip] += 1

if __name__ == "__main__":
    NULL_scan_counts = {}
    FIN_scan_counts = {}
    XMAS_scan_counts = {}

    for packet in rdpcap(sys.argv[1]):
        parsePacket(packet)

    for ip, count in NULL_scan_counts.items():
        print(f"NULLScan, IP:{ip}, COUNT:{count}")

    for ip, count in FIN_scan_counts.items():
        print(f"FINScan, IP:{ip}, COUNT:{count}")

    for ip, count in XMAS_scan_counts.items():
        print(f"XMASScan, IP:{ip}, COUNT:{count}")
