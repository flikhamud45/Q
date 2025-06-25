from scapy.all import *
import random

FROM_IFACE = "enp0s8"
TO_IFACE = "enp0s9"

FROM_IFACE_MAC = get_if_hwaddr(FROM_IFACE)
TO_FACE_MAC = get_if_hwaddr(TO_IFACE)

FROM_IFACE_IP = get_if_addr(FROM_IFACE)
TO_IFACE_IP = get_if_addr(TO_IFACE)

port_table = {}

def send_packet(packet):
    if packet.sniffed_on == FROM_IFACE:
        if IP in packet and (TCP in packet or UDP in packet):
            packet[IP].src = TO_IFACE_IP
            if not (pack.sport in port_table and port_table[packet.sport] == packet[IP].src):
                while packet.sport in port_table:
                    packet.sport = random.randint(1024, 65535)
                port_table[packet.sport] = packet[IP].src
        sendp(packet, iface=TO_IFACE, verbose=False)
    else:
        if IP in packet and (TCP in packet or UDP in packet) and packet.dport in port_table:
            packet[IP].dst = port_table[packet.dport]
        sendp(packet, iface=FROM_IFACE, verbose=False)

def main():
    sniff(iface=[FROM_IFACE, TO_IFACE], prn=send_packet)


if __name__ == "__main__":
    main()