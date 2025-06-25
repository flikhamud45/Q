from scapy.all import *

FROM_IFACE = "enp0s8"
TO_IFACE = "enp0s9"

FROM_IFACE_MAC = get_if_hwaddr(FROM_IFACE)
TO_FACE_MAC = get_if_hwaddr(TO_IFACE)

def send_packet(packet):
    if packet.sniffed_on == FROM_IFACE:
        if Ether in packet:
            packet[Ether].src = TO_FACE_MAC
        send(packet, iface=TO_IFACE, verbose=False)
    else:
        if Ether in packet:
            packet[Ether].src = FROM_IFACE_MAC
        send(packet, iface=FROM_IFACE, verbose=False)

def main():
    sniff(iface=[FROM_IFACE, TO_IFACE], prn=send_packet)


if __name__ == "__main__":
    main()