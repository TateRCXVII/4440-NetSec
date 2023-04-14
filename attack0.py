#!/usr/bin/python3

import logging
import sys
import re
from scapy.all import *
from collections import defaultdict

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def check_ftp_credentials(data):
    user_regex = re.compile(r'USER (.*?)\r?\n', re.MULTILINE | re.IGNORECASE)
    pass_regex = re.compile(r'PASS (.*?)\r?\n', re.MULTILINE | re.IGNORECASE)

    user_match = user_regex.search(data)
    pass_match = pass_regex.search(data)

    if user_match and pass_match:
        print(f'FTP, USERNAME:{user_match.group(1)}, PASSWORD:{pass_match.group(1)}')
        return True
    return False

def check_imap_credentials(data):
    user_match = re.search(r'(?i)LOGIN\s+([^\s]+)\s+([^\s\*]+)(?!\s+completed)', data)
    if user_match:
        print(f"IMAP, USERNAME:{user_match.group(1)}, PASSWORD:{user_match.group(2)}")
        return True
    return False



tcp_streams = defaultdict(str)

def parsePacket(packet):
    if not packet.haslayer("TCP"):
        return

    if packet.haslayer("Raw"):
        try:
            data = packet["Raw"].load.decode('utf-8')
        except UnicodeDecodeError:
            return

        tcp_stream_key = (packet["IP"].src, packet["IP"].dst, packet["TCP"].sport, packet["TCP"].dport)
        tcp_streams[tcp_stream_key] += data

        # Split the accumulated data into lines
        lines = tcp_streams[tcp_stream_key].splitlines(keepends=True)

        # Check if the last line is complete (ends with a line break)
        if lines and lines[-1].endswith(('\n', '\r\n')):
            accumulated_data = "".join(lines)
            if check_ftp_credentials(accumulated_data) or check_imap_credentials(accumulated_data):
                tcp_streams[tcp_stream_key] = ""
            else:
                # Remove processed lines except the last one (which might be incomplete)
                tcp_streams[tcp_stream_key] = lines[-1]

if __name__ == "__main__":
    print('Analyzing packets...')
    for packet in rdpcap(sys.argv[1]):
        parsePacket(packet)
