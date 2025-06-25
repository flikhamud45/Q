from scapy.all import *
from typing import Dict, Tuple
import random

FROM_IFACE = "enp0s8"
TO_IFACE = "enp0s9"

FROM_IFACE_MAC = get_if_hwaddr(FROM_IFACE)
TO_IFACE_MAC = get_if_hwaddr(TO_IFACE)

FROM_IFACE_IP = get_if_addr(FROM_IFACE)
TO_IFACE_IP = get_if_addr(TO_IFACE)

port_table: Dict[Tuple[str, int], int] = {}
port_table_inv: Dict[int, Tuple[str, int]] = {}
port_table_times: Dict[datetime, int] = {}


def send_packet(packet):
    if packet.sniffed_on == FROM_IFACE:
        if Ether in packet and IP in packet and (TCP in packet or UDP in packet):
            if (packet[IP].src, packet[IP].sport) not in port_table:
                avialable_ports = list(set(range(1024, 65536)) - set(port_table.values()))
                if len(avialable_ports) == 0:
                    new_sport = port_table_times[min(port_table_times.keys())]
                else:
                    new_sport = random.choice(avialable_ports)
                port_table[(packet[IP].src, packet.sport)] = new_sport
                port_table_inv[new_sport] = (packet[IP].src, packet.sport)
                

            packet.sport = port_table[(packet[IP].src, packet.sport)]
            packet[Ether].src = TO_IFACE_MAC
            packet[IP].src = TO_IFACE_IP
            port_table_times[datetime.now()] = packet.sport
            send(packet, iface=TO_IFACE, verbose=True)
    else:
        if Ether in packet and IP in packet and (TCP in packet or UDP in packet) and packet.dport in port_table_inv:
            port_table_times[datetime.now()] = packet.dport
            packet[Ether].src = FROM_IFACE_MAC
            packet[IP].src = FROM_IFACE_IP
            packet.dport, packet[IP].dst = port_table_inv[packet.dport]
            send(packet, iface=FROM_IFACE, verbose=True)

def main():
    sniff(iface=[FROM_IFACE, TO_IFACE], prn=send_packet)


if __name__ == "__main__":
    main()