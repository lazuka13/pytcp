import argparse
import pprint
import socket

from pytcp.ethernet import EthernetPacket, ETH_P_ALL, ETH_P_IP
from pytcp.ip import IPPacket
from pytcp.tcp import TCPPacket

parser = argparse.ArgumentParser()
parser.add_argument('--type', dest='type')


def sender():
    sock_send = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
    message = bytes('hell'.encode('utf-8'))

    tcp_packet = TCPPacket(source_port=10000, destination_port=20000, source_ip="10.0.0.10",
                           destination_ip="10.0.0.11", seq=0, ack=0, payload=message)
    pprint.pprint(tcp_packet.__dict__)
    print(tcp_packet.calculate_checksum())
    ip_packet = IPPacket(source_ip_addr="10.0.0.10",
                         destination_ip_addr="10.0.0.11",
                         payload=tcp_packet.serialize()).serialize()
    ethernet_packet = EthernetPacket(source_mac="08:00:27:cc:09:cd",
                                     destination_mac="08:00:27:f9:6c:24",
                                     protocol=ETH_P_IP, payload=ip_packet).serialize()
    sock_send.sendto(ethernet_packet, ('eth1', ETH_P_IP))
    sock_send.close()


def receiver():
    sock_recv = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    data, address = sock_recv.recvfrom(65536)
    ethernet_packet = EthernetPacket.deserialize(data)
    pprint.pprint(ethernet_packet.__dict__)
    ip_packet = IPPacket.deserialize(ethernet_packet.payload)
    pprint.pprint(ip_packet.__dict__)
    tcp_packet = TCPPacket.deserialize(source_ip=ip_packet.source_ip_addr,
                                       destination_ip=ip_packet.destination_ip_addr,
                                       payload=ip_packet.payload)
    pprint.pprint(tcp_packet.__dict__)
    print(tcp_packet.validate_checksum())
    sock_recv.close()


if __name__ == '__main__':
    args = parser.parse_args()
    if args.type == "sender":
        sender()
    else:
        receiver()
