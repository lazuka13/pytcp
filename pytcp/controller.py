import logging
import socket
import threading
import typing

from scapy.layers.l2 import getmacbyip
from scapy.route import Route

from pytcp.ethernet import ETH_P_ALL, ETH_P_IP, EthernetPacket
from pytcp.ip import IPPacket
from pytcp.socket import Socket, State
from pytcp.tcp import TCPPacket

TCP_RECV_BUFFER = 65536


# does not support implicit binding
# so you need to call bind before calling listen/connect


class Controller:
    def __init__(self):
        self.interface_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        self.binded_sockets: typing.Dict[int, Socket] = dict()

        self.__thread = threading.Thread(target=self.run, args=(self,))
        self.__lock = threading.Lock()
        self.__off = False
        self.__thread.start()

    def check_off(self):
        with self.__lock:
            return self.__off

    def bind(self, socket_obj, source_ip, source_port, destination_ip, destination_port):
        bind_id = hash((source_ip, source_port, destination_ip, destination_port))
        with self.__lock:
            if bind_id in self.binded_sockets:
                raise Exception(f"can't bind socket - address already taken")
            self.binded_sockets[bind_id] = socket_obj

    def unbind(self, source_ip, source_port, destination_ip, destination_port):
        bind_id = hash((source_ip, source_port, destination_ip, destination_port))
        with self.__lock:
            self.binded_sockets.pop(bind_id)

    def stop(self):
        with self.__lock:
            self.__off = True
        self.__thread.join()

    def send_packet(self, tcp_packet):
        with self.__lock:
            ip_packet = IPPacket(source_ip_addr=tcp_packet.source_ip,
                                 destination_ip_addr=tcp_packet.destination_ip,
                                 payload=tcp_packet.serialize()).serialize()
            ethernet_packet = EthernetPacket(source_mac=getmacbyip(tcp_packet.source_ip),
                                             destination_mac=getmacbyip(tcp_packet.destination_ip),
                                             protocol=ETH_P_IP, payload=ip_packet).serialize()
            self.interface_socket.sendto(ethernet_packet,
                                         (Route().route(tcp_packet.destination_ip)[0], ETH_P_ALL))

    def run(self):
        while not self.check_off():
            # poll socket
            data_bytes, address = self.interface_socket.recvfrom(TCP_RECV_BUFFER)

            # parse packets
            try:
                ethernet_packet = EthernetPacket.deserialize(data_bytes)
                ip_packet = IPPacket.deserialize(ethernet_packet.payload)
                tcp_packet = TCPPacket.deserialize(source_ip=ip_packet.source_ip_addr,
                                                   destination_ip=ip_packet.destination_ip_addr,
                                                   payload=ip_packet.payload)
            except Exception as err:
                logging.error(f"failed to parse: {err}")
                continue

            with self.__lock:
                # send to socket (tcp_packet.source_ip == socket.destination_ip)
                bind_id = hash((tcp_packet.source_ip, tcp_packet.source_port,
                                tcp_packet.destination_ip, tcp_packet.destination_port))
                if bind_id in self.binded_sockets:
                    socket_obj = self.binded_sockets[bind_id]
                    if socket_obj.state == State.Listening or \
                            socket_obj.state == State.Connected or \
                            socket_obj.state == State.Connecting or \
                            socket_obj.state == State.Accepting or \
                            socket_obj.state == State.Accepted:
                        # port is opened, socket can process
                        socket_obj.process(tcp_packet)
                        self.__lock.release()
                        continue

            # no socket - send RST
            rst_packet = TCPPacket(
                source_ip=tcp_packet.destination_ip,
                destination_ip=tcp_packet.source_ip,
                source_port=tcp_packet.destination_ip,
                destination_port=tcp_packet.source_port,
                seq=0, ack=0, payload=bytes()
            )
            rst_packet.flag_rst = 1
            self.send_packet(rst_packet)

    def socket(self):
        return Socket(self)
