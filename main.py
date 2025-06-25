from enum import Enum
from scapy.all import get_if_hwaddr, conf, get_if_addr
import struct
from typing import Dict, List, Optional, Tuple

iface = "wlan0"
MY_MAC = get_if_hwaddr(iface).lower()
MY_IP = get_if_addr(iface)

MAC_BROADCAST = "FF:FF:FF:FF:FF:FF"
DEFAULT_GATEWAY_MAC = "AA:BB:CC:DD:EE:FF"
ETHER_HEADER = struct.Struct("6s6sh")


ARP_STRUCT = struct.Struct("hhBBh")

MAC_HW_TYPE = 1
IPv4_IP_TYPE = 2048
MAC_HW_SIZE = 6
IPv4_IP_SIZE = 4

MAX_ETHER_SIZE = 1500

IP_STRUCT = struct.Struct("BBHHHBBH4s4s")

ICMP_STRUCT = struct.Struct("BBH")
ECHO_STRUCT = struct.Struct("HH")
# dict of (src_ip, packetid) : dict(fragment_pos: data)
ip_database: Dict[Tuple[bytes, int], Dict[int, bytes]] = {}

ip_id = 0


class EtherType(Enum):
    ip = 0x0800
    arp = 0x0806

class ArpOpcode(Enum):
    arp_request = 1
    arp_answer = 2

class IpType(Enum):
    TCP = 17
    UDP = 1
    ICMP = 6

class IcmpType(Enum):
    echo_reply = 0
    unreachble = 3
    echo_request = 8


def mac_bytes_to_str(mac: bytes):
    s = ""
    for b in mac:
        s += hex(b)[2:] + ":"
    return s[:-1]

def mac_str_to_bytes(mac: str) -> bytes:
    return b"".join(int.to_bytes(int(b, 16), 1, "big") for b in mac.lower().split(":"))


def ip_str_to_bytes(ip: str) -> bytes:
    return b"".join(int.to_bytes(int(b), 1, "big") for b in ip.split("."))

def ip_bytes_to_str(ip: bytes) -> str:
    return ".".join(str(x) for x in ip)


def recv_ether(sock):
    ether_pack = sock.recv_raw()[1]
    opening, data = ether_pack[:ETHER_HEADER.size], ether_pack[ETHER_HEADER.size:]
    src_mac, dst_mac, ether_type = ETHER_HEADER.unpack(opening)
    if mac_bytes_to_str(dst_mac) == MY_MAC:
        handle_ether_packet(sock, data, EtherType(ether_type))

def send_ether(sock, src_mac: bytes, dst_mac: bytes, ether_type: EtherType, data: bytes):
    sock.send(ETHER_HEADER.pack(src_mac, dst_mac, ether_type.value) + data)


def handle_ether_packet(sock, data: bytes, ether_type: EtherType):
    if ether_type in ETHER_PROTO_HANDLES:
        ETHER_PROTO_HANDLES[EtherType(ether_type)](sock, data)

def is_data_complete(ip_data: Dict[int, bytes], data_size) -> bool:
    data_so_far: List[Tuple[int, int]] = sorted([(x[0], len(x[1])) for x in ip_data.items()])
    data_so_far_interval = [data_so_far[0][0], data_so_far[0][1]-1]
    if data_so_far_interval[0] != 0:
        return False
    for pos, s in data_so_far:
        if pos > data_so_far_interval[0]:
            return False
        data_so_far_interval[1] = pos + s - 1
    return data_so_far_interval[1] >= data_size-1
        
    
def build_ip_data(ip_data: Dict[int, bytes], data_size: int) -> bytes:
    ans = bytearray(data_size)
    for pos, data in ip_data.items():
        ans[pos:pos+len(data)] = data
    return ans

def handle_ip(sock, data: bytes):
    version_and_header_length, Tos, packet_length, id, fragment, ttl, proto, checksum, src_ip, dst_ip = IP_STRUCT.unpack(data[:IP_STRUCT.size])
    version = version_and_header_length ^ ((1 << 4) - 1)
    header_length = 4 * (version_and_header_length >> 4)
    ip_data = data[header_length:]
    if version != 4:
        return
    if dst_ip != ip_str_to_bytes(MY_IP):
        return
    
    fragment_metadata = fragment ^ ((1 << 3) - 1)
    fragment_pos = (fragment >> 3) * 8
    if fragment_metadata ^ 0b10 == 0:
        if (src_ip, id) not in ip_database:
            ip_database[(src_ip, id)] = {}
        
        ip_database[(src_ip, id)][fragment_pos] = ip_data
        if is_data_complete(ip_database[(src_ip, id)], packet_length-20*len(ip_database[(src_ip, id)])):
            complete_data = build_ip_data(ip_database[(src_ip, id)], 20*len(ip_database[(src_ip, id)]))
            handle_4_layer(sock, complete_data, IpType(proto), src_ip)
    else:
        handle_4_layer(sock, data, IpType(proto), src_ip)
        
def send_ip(sock, dst_ip: bytes, ip_type: IpType, data: bytes):
    version_and_header_length = 4 | (20 << 4)
    Tos = 0
    packet_length = ((len(data) + IP_STRUCT.size) // MAX_ETHER_SIZE + 1) * IP_STRUCT.size + len(data)
    global ip_id
    id = ip_id
    ip_id += 1
    fragment = 0
    ttl = 128
    proto = ip_type.value
    src_ip = ip_str_to_bytes(MY_IP)
    while data:
        ether_data = data[:MAX_ETHER_SIZE-IP_STRUCT.size]
        data = data[MAX_ETHER_SIZE-IP_STRUCT.size:]
        fragment += MAX_ETHER_SIZE # MAX_ETHER_SIZE % 4 is 0 so this is ok        
        if len(data) == 0:
            fragment ^= 1 # label as the last fragment
        checksum = 0
        ip_header = IP_STRUCT.pack(version_and_header_length, Tos, packet_length, id, fragment, ttl, proto, checksum, src_ip, dst_ip)
        checksum = calc_checksum(ip_header + ether_data)
        ip_header = IP_STRUCT.pack(version_and_header_length, Tos, packet_length, id, fragment, ttl, proto, checksum, src_ip, dst_ip)
        send_ether(sock, mac_str_to_bytes(MY_MAC), mac_str_to_bytes(DEFAULT_GATEWAY_MAC), EtherType.ip, ip_header+ether_data)
        

def handle_4_layer(sock, data: bytes, proto: IpType, ip_src: bytes):
    IP_PROTO_HANDLES[proto](sock, data, ip_src)


def handle_icmp(sock, data: bytes, ip_src: bytes):
    icmp_type, code, checksum = ICMP_STRUCT.unpack(data[:ICMP_STRUCT.size])
    icmp_type = IcmpType(icmp_type)
    if icmp_type in [IcmpType.echo_reply, IcmpType.echo_request]:
        id, seq = ECHO_STRUCT.unpack(data[ICMP_STRUCT.size:ICMP_STRUCT.size+ECHO_STRUCT.size])
        payload = data[ICMP_STRUCT.size+ECHO_STRUCT.size:]
    if icmp_type == IcmpType.echo_reply:
        print(f"got ping reply from {ip_bytes_to_str(ip_src)} with id {id}")
    elif icmp_type == IcmpType.echo_request:
        send_icmp_reply(sock, ip_src, id, payload)

def send_icmp_reply(sock, ip_dst: bytes, id:int, payload: bytes):
    send_icmp(sock, IcmpType.echo_reply, ip_dst, id)

def send_icmp_request(sock, ip_dst: bytes):
    send_icmp(sock, IcmpType.echo_reply, ip_dst)


def send_icmp(sock, icmp_type: IcmpType, ip_dst: bytes, id: Optional[int] = None, payload: bytes = b'abcd', code: int = 0):
    header = ICMP_STRUCT.pack(icmp_type.value, code, 0)
    icmp_data = b''
    if icmp_type in [IcmpType.echo_reply, IcmpType.echo_request]:
        icmp_data = ECHO_STRUCT.pack(id, 0) + payload
    else:
        return 
    header = ICMP_STRUCT.pack(icmp_type.value, code, calc_checksum(header+icmp_data))
    send_ip(sock, ip_dst, header+icmp_data)

def calc_checksum(data: bytes) -> int:
    return 0


    

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
IP_PROTO_HANDLES = {IpType.ICMP: handle_icmp}

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