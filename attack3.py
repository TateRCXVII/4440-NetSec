#!/usr/bin/python3

import logging
import sys
import hashlib
from scapy.all import *

# Disable scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# Extract the file name from the FTP RETR command in the packet data
def extract_file_name(data):
    regex = r"RETR (.+)"
    match = re.search(regex, data)
    if match:
        return match.group(1).strip().lower()
    return None

# Extract the IP address and port for the passive FTP data connection
def extract_pasv_ip_port(data):
    regex = r"Entering Passive Mode \((\d+,\d+,\d+,\d+),(\d+),(\d+)\)"
    match = re.search(regex, data)
    if match:
        ip = ".".join(match.group(1).split(","))
        port = int(match.group(2)) * 256 + int(match.group(3))
        return ip, port
    return None, None

# Process the packets to extract file name, passive connection IP and port, and file content
def parsePacket(packet, file_data):
    if not packet.haslayer("TCP"):
        return None

    data = bytes(packet["TCP"].payload).decode('utf-8', 'replace')

    # Extract the file name if it hasn't been found yet
    if not file_data["file_name"]:
        file_name = extract_file_name(data)
        if file_name:
            file_data["file_name"] = file_name

    # Extract the passive IP and port if they haven't been found yet
    if not file_data["pasv_ip"] or not file_data["pasv_port"]:
        pasv_ip, pasv_port = extract_pasv_ip_port(data)
        if pasv_ip and pasv_port:
            file_data["pasv_ip"] = pasv_ip
            file_data["pasv_port"] = pasv_port

    # Collect the file content if all necessary information has been found
    if packet.haslayer("Raw") and file_data["file_name"] and file_data["pasv_ip"] and file_data["pasv_port"]:
        if (packet["IP"].src == file_data["pasv_ip"] and packet["TCP"].sport == file_data["pasv_port"]) or (packet["IP"].dst == file_data["pasv_ip"] and packet["TCP"].dport == file_data["pasv_port"]):
            file_data["file_content"].append(packet["Raw"].load)

# Main function
if __name__ == "__main__":
    # Initialize the file data dictionary
    file_data = {
        "file_name": None,
        "file_content": [],
        "pasv_ip": None,
        "pasv_port": None,
    }

    # Iterate through the packets in the pcap file and process them
    for packet in rdpcap(sys.argv[1]):
        parsePacket(packet, file_data)

    # Save the extracted file if a file name has been found
    if file_data["file_name"]:
        with open(file_data["file_name"], "wb") as f:
            for content in file_data["file_content"]:
                f.write(content)

        print(f'Generated file "{file_data["file_name"]}"')

    else:
        print("No files found.")
