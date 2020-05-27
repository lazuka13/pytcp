import argparse
import pprint
import socket

from pytcp.ethernet import EthernetPacket, ETH_P_ALL

parser = argparse.ArgumentParser()
parser.add_argument('--type', dest='type')


def sender():
    sock_send = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))

    message = bytes('hell'.encode('utf-8'))
    ethernet_packet = EthernetPacket(source_mac="08:00:27:cc:09:cd",
                                     destination_mac="08:00:27:f9:6c:24",
                                     protocol=ETH_P_ALL,
                                     payload=message)
    pprint.pprint(ethernet_packet.__dict__)
    print(ethernet_packet.serialize())
    sock_send.sendto(ethernet_packet.serialize(), ('eth1', ETH_P_ALL))
    sock_send.close()


def receiver():
    sock_recv = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    data, address = sock_recv.recvfrom(65536)
    print(data, address)
    deserialized = EthernetPacket.deserialize(data)
    pprint.pprint(deserialized.__dict__)
    sock_recv.close()


if __name__ == '__main__':
    args = parser.parse_args()
    if args.type == "sender":
        sender()
    else:
        receiver()
