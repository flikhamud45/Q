from scapy.all import *
import random
from typing import Dict

FROM_IFACE = "enp0s8"
TO_IFACE = "enp0s9"

FROM_IFACE_MAC = get_if_hwaddr(FROM_IFACE)
TO_FACE_MAC = get_if_hwaddr(TO_IFACE)

FROM_IFACE_IP = get_if_addr(FROM_IFACE)
TO_IFACE_IP = get_if_addr(TO_IFACE)

port_table: Dict[int, str] = {}

# list of firewall rules in the format (protocol, port, allow)
inbound_firewall_rules: List[Tuple[str, int, bool]] = [("UDP", 12345, False)]


def send_packet(packet):
    if packet.sniffed_on == FROM_IFACE:
        if Ether in packet and IP in packet and (TCP in packet or UDP in packet):
            packet[Ether].src = TO_FACE_MAC
            packet[IP].src = TO_IFACE_IP
            if not (pack.sport in port_table and port_table[packet.sport] == packet[IP].src):
                while packet.sport in port_table:
                    packet.sport = random.randint(1024, 65535)
                port_table[packet.sport] = packet[IP].src
        sendp(packet, iface=TO_IFACE, verbose=False)
    else:
        for protocol, port, allow in inbound_firewall_rules:
            # the first matching rule will be applied
            if (protocol == 'TCP' and TCP in packet or protocol == 'UDP' and UDP in packet) and packet.dport == port:
                if not allow:
                    return
                if allow:
                    break
            
        if IP in packet and (TCP in packet or UDP in packet) and packet.dport in port_table:
            packet[Ether].src = FROM_IFACE_MAC
            packet[IP].dst = port_table[packet.dport]
        sendp(packet, iface=FROM_IFACE, verbose=False)

def main():
    sniff(iface=[FROM_IFACE, TO_IFACE], prn=send_packet)


if __name__ == "__main__":
    main()