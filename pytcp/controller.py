import logging
import random
import socket
import threading
import typing

from scapy.layers.l2 import getmacbyip, get_if_hwaddr
from scapy.route import Route

from pytcp.ethernet import ETH_P_ALL, ETH_P_IP, EthernetPacket
from pytcp.ip import IPPacket
from pytcp.socket import Socket, State
from pytcp.tcp import TCPPacket

TCP_RECV_BUFFER = 65536

logging.basicConfig(level=logging.DEBUG)


# does not support implicit binding
# so you need to call bind before calling listen/connect


class Controller:
    def __init__(self):
        self.interface_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))

        self.binded_sockets: typing.Dict[int, Socket] = dict()
        self.binded_ports = set()

        self._thread = threading.Thread(target=self.run)
        self._lock = threading.Lock()
        self._off = False
        self._thread.start()

    def get_free_port(self):
        if len(self.binded_ports) == 65536 - 49152 - 1:
            raise Exception("can't find free port")
        with self._lock:
            while True:
                port = random.randint(49152, 65536)
                if port not in self.binded_ports:
                    return port

    def check_off(self):
        with self._lock:
            return self._off

    def bind(self, socket_obj, source_ip, source_port, destination_ip, destination_port):
        bind_id = hash((source_ip, source_port, destination_ip, destination_port))
        with self._lock:
            if bind_id in self.binded_sockets:
                raise Exception(f"can't bind socket - address already taken")
            self.binded_sockets[bind_id] = socket_obj
            self.binded_ports.add(source_ip)

    def unbind(self, source_ip, source_port, destination_ip, destination_port):
        bind_id = hash((source_ip, source_port, destination_ip, destination_port))
        with self._lock:
            self.binded_sockets.pop(bind_id)
            self.binded_ports.remove(source_ip)

    def stop(self):
        with self._lock:
            self._off = True
        self._thread.join()

    def send_packet(self, tcp_packet):
        with self._lock:
            interface = Route().route(tcp_packet.destination_ip)[0]
            ip_packet = IPPacket(source_ip_addr=tcp_packet.source_ip,
                                 destination_ip_addr=tcp_packet.destination_ip,
                                 payload=tcp_packet.serialize())
            ethernet_packet = EthernetPacket(source_mac=get_if_hwaddr(interface),
                                             destination_mac=getmacbyip(tcp_packet.destination_ip),
                                             protocol=ETH_P_IP, payload=ip_packet.serialize())
            self.interface_socket.sendto(ethernet_packet.serialize(),
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
                if tcp_packet.destination_port < 1024 or tcp_packet.source_port < 1024:
                    continue
            except Exception:
                continue

            with self._lock:
                connect_id = hash((tcp_packet.destination_ip, tcp_packet.destination_port,
                                   tcp_packet.source_ip, tcp_packet.source_port))
                listen_id = hash((tcp_packet.destination_ip, tcp_packet.destination_port, None, None))
                if connect_id in self.binded_sockets:
                    socket_obj = self.binded_sockets[connect_id]
                elif listen_id in self.binded_sockets:
                    socket_obj = self.binded_sockets[listen_id]
                else:
                    socket_obj = None

                if socket_obj and \
                        (socket_obj.state == State.Listening or
                         socket_obj.state == State.Connected or
                         socket_obj.state == State.Connecting or
                         socket_obj.state == State.Accepting or
                         socket_obj.state == State.Accepted or
                         socket_obj.state.Listening):
                    # port is opened, socket can process
                    socket_obj.process(tcp_packet)
                    continue

            # no socket - send RST
            rst_packet = TCPPacket(
                source_ip=tcp_packet.source_ip,
                destination_ip=tcp_packet.destination_ip,
                source_port=tcp_packet.source_port,
                destination_port=tcp_packet.destination_port,
                seq=0, ack=0, payload=bytes()
            )
            rst_packet.flag_rst = 1
            self.send_packet(rst_packet)

    def socket(self):
        return Socket(self)
