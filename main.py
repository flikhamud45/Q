from enum import Enum
from scapy.all import get_if_hwaddr, conf, get_if_addr
import struct

iface = "wlan0"
MY_MAC = get_if_hwaddr(iface).lower()
MY_IP = get_if_addr(iface)

MAC_BROADCAST = "FF:FF:FF:FF:FF:FF"

ETHER_HEADER = struct.Struct("6s6sh")


ARP_STRUCT = struct.Struct("hhBBh")

MAC_HW_TYPE = 1
IPv4_IP_TYPE = 2048
MAC_HW_SIZE = 6
IPv4_IP_SIZE = 4

class EtherType(Enum):
    ip = 0x0800
    arp = 0x0806

class ArpOpcode(Enum):
    arp_request = 1
    arp_answer = 2



def mac_bytes_to_str(mac: bytes):
    s = ""
    for b in mac:
        s += hex(b)[2:] + ":"
    return s[:-1]

def mac_str_to_bytes(mac: str) -> bytes:
    return b"".join(int.to_bytes(int(b, 16), 1, "big") for b in mac.lower().split(":"))


def ip_str_to_bytes(ip: str) -> bytes:
    return b"".join(int.to_bytes(int(b), 1, "big") for b in ip.split("."))



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
    arp_header, arp_data = data[:ARP_STRUCT.size], data[ARP_STRUCT.size:]
    hw_type, ip_type, hw_size, ip_size, opcode = ARP_STRUCT.unpack(arp_header)
    hw_src, ip_src, hw_dst, ip_dst = struct.unpack(f"{hw_size}s{ip_size}s{hw_size}s{ip_size}s", arp_data)
    if hw_type == MAC_HW_TYPE and ip_src == IPv4_IP_TYPE:
        if opcode == ArpOpcode.arp_request:
            if ip_dst == ip_str_to_bytes(MY_IP):
                send_arp_answer(sock, hw_src, ip_src)
        elif opcode == ArpOpcode.arp_answer:
            print(f"{ip_src} is on {hw_src}")


ETHER_PROTO_HANDLES = {EtherType.ip: handle_ip, EtherType.arp: handle_arp}


def send_arp(sock, opcode: ArpOpcode, hw_src: bytes, ip_src: bytes, hw_dst: bytes, ip_dst: bytes, hw_type: int = MAC_HW_TYPE, ip_type: int = IPv4_IP_TYPE, hw_size: int = MAC_HW_SIZE, ip_size: int = IPv4_IP_SIZE):
    arp_header = ARP_STRUCT.pack(hw_type, ip_type, hw_size, ip_size, opcode.value)
    arp_data = struct.pack(f"{hw_size}s{ip_size}s{hw_size}s{ip_size}s", hw_src, ip_src, hw_dst, ip_dst)
    send_ether(sock, hw_src, hw_dst, EtherType.arp, arp_header+arp_data)

def send_arp_request(sock, ip: str):
    send_arp(sock, ArpOpcode.arp_request, mac_str_to_bytes(MY_MAC), ip_str_to_bytes(MY_IP), mac_str_to_bytes(MAC_BROADCAST), ip_str_to_bytes(ip))

def send_arp_answer(sock, hw_dst: bytes, ip_dst: bytes):
    send_arp(sock, ArpOpcode.arp_answer, mac_str_to_bytes(MY_MAC), ip_str_to_bytes(MY_IP), hw_dst, ip_dst)

def main():
    sock = conf.L2socket(promisc=True)
    while True:
        recv_ether(sock)
    

if __name__ == "__main__":
    main()