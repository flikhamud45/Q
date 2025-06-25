from enum import Enum
from scapy.all import get_if_hwaddr, conf, get_if_addr
import struct

iface = "wlan0"
MY_MAC = get_if_hwaddr(iface).lower()

ETHER_START_PREAMBLE = b'\xaa'
ETHER_END_PREAMBLE = b'\xaa'
ETHER_START_PREAMBLE_LEN = 7
ETHER_PREAMBLE = ETHER_START_PREAMBLE * ETHER_START_PREAMBLE + ETHER_END_PREAMBLE

ETHER_HEADER = struct.Struct("6s6sh")

ARP_STRUCT = struct.Struct("hhBBh6s")

class EtherType(Enum):
    ip = 0x0800
    arp = 0x0806



def mac_bytes_to_str(mac: bytes):
    s = ""
    for b in mac:
        s += hex(b)[2:] + ":"
    return s[:-1]

def mac_str_to_bytes(mac: str) -> bytes:
    return b"".join(int.to_bytes(int(b), 1, "big") for b in mac.lower().split(":"))


def recv_ether(sock):
    ether_pack = sock.recv_raw()[1]
    opening, data = ether_pack[:ETHER_HEADER.size], ether_pack[ETHER_HEADER.size:]
    src_mac, dst_mac, ether_type = ETHER_HEADER.unpack(opening)
    if mac_bytes_to_str(dst_mac) == MY_MAC:
        handle_ether_packet(sock, data, ether_type)

def send_ether(sock, src_mac: bytes, dst_mac: bytes, ether_type: EtherType, data: bytes):
    sock.send(ETHER_HEADER.pack(src_mac, dst_mac, ether_type.value) + data)


def handle_ether_packet(sock, data: bytes, ether_type: int):
    ether_type = EtherType(ether_type)
    if ether_type in ETHER_PROTO_HANDLES:
        ETHER_PROTO_HANDLES[EtherType(ether_type)](sock, data)

def handle_ip(sock, data: bytes):
    pass

def handle_arp(sock, data: bytes):
    pass

ETHER_PROTO_HANDLES = {EtherType.ip: handle_ip, EtherType.arp: handle_arp}



def send_arp_request(sock):
    pass

def main():
    sock = conf.L2socket(promisc=True)
    while True:
        recv_ether(sock)
    

if __name__ == "__main__":
    main()