from enum import Enum
from scapy.all import get_if_hwaddr, conf
import struct

iface = "wlan0"
ETHER_START_PREAMBLE = b'\xaa'
ETHER_END_PREAMBLE = b'\xaa'
ETHER_START_PREAMBLE_LEN = 7
ETHER_PREAMBLE = ETHER_START_PREAMBLE * ETHER_START_PREAMBLE + ETHER_END_PREAMBLE

ETHER_HEADER = struct.Struct("6b6bh")
MY_MAC = get_if_hwaddr(iface).lower()

class EtherType(Enum):
    ip = 0x0800
    arp = 0x0806

def mac_bytes_to_str(mac: bytes):
    s = ""
    for b in mac:
        s += hex(b)[2:] + ":"
    return s[:-1]


def recv_ether(sock):
    ether_pack = sock.recv_raw()[1]
    opening, data = ether_pack[:ETHER_HEADER.size], ether_pack[ETHER_HEADER.size:]
    src_mac, dst_mac, ether_type = ETHER_HEADER.unpack(opening)
    if mac_bytes_to_str(dst_mac) == MY_MAC:
        handle_packet(data, ether_type)

def handle_packet(data, ether_type):
    if ether_type == EtherType.ip:
        handle_ip(data)
    elif ether_type == EtherType.arp:
        handle_arp(data)
    else:
        pass

def handle_ip(data):
    pass

def handle_arp(data):
    pass


def main():
    sock = conf.L2socket(promisc=True)
    while True:
        recv_ether(sock)
    

if __name__ == "__main__":
    main()