#!/usr/bin/python3

import logging
import sys
import hashlib
from scapy.all import *

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def extract_file_name(data):
    regex = r"RETR (.+)"
    match = re.search(regex, data)
    if match:
        return match.group(1).strip().lower()
    return None

def extract_pasv_ip_port(data):
    regex = r"Entering Passive Mode \((\d+,\d+,\d+,\d+),(\d+),(\d+)\)"
    match = re.search(regex, data)
    if match:
        ip = ".".join(match.group(1).split(","))
        port = int(match.group(2)) * 256 + int(match.group(3))
        return ip, port
    return None, None

def parsePacket(packet, file_data):
    if not packet.haslayer("TCP"):
        return None

    data = bytes(packet["TCP"].payload).decode('utf-8', 'replace')

    if not file_data["file_name"]:
        file_name = extract_file_name(data)
        if file_name:
            file_data["file_name"] = file_name

    if not file_data["pasv_ip"] or not file_data["pasv_port"]:
        pasv_ip, pasv_port = extract_pasv_ip_port(data)
        if pasv_ip and pasv_port:
            file_data["pasv_ip"] = pasv_ip
            file_data["pasv_port"] = pasv_port

    if packet.haslayer("Raw") and file_data["file_name"] and file_data["pasv_ip"] and file_data["pasv_port"]:
        if (packet["IP"].src == file_data["pasv_ip"] and packet["TCP"].sport == file_data["pasv_port"]) or (packet["IP"].dst == file_data["pasv_ip"] and packet["TCP"].dport == file_data["pasv_port"]):
            file_data["file_content"].append(packet["Raw"].load)

if __name__ == "__main__":
    file_data = {
        "file_name": None,
        "file_content": [],
        "pasv_ip": None,
        "pasv_port": None,
    }

    for packet in rdpcap(sys.argv[1]):
        parsePacket(packet, file_data)

    if file_data["file_name"]:
        with open(file_data["file_name"], "wb") as f:
            for content in file_data["file_content"]:
                f.write(content)

        print(f'Generated file "{file_data["file_name"]}"')

    else:
        print("No files found.")
