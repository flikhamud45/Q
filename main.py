from scapy.all import *

FROM_IFACE = "enp0s8"
TO_IFACE = "enp0s9"

def send_packet(packet):
    sendp(packet, iface=TO_IFACE, verbose=False)

def main():
    sniff(iface=FROM_IFACE, prn=send_packet)


if __name__ == "__main__":
    main()