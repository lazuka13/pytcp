import enum
import logging
import threading
import typing

from pytcp.tcp import TCPPacket
from pytcp.configuration import MSS

logging.basicConfig(level=logging.DEBUG)

ACK_TIMEOUT = 0.01
MSS = 536


class State(enum.Enum):
    Zero = 0  # uninitialized
    Binded = 1  # source address specified

    Listening = 2  # source address specified, listening socket, loop running
    Accepting = 3  # source address specified, accepting connection
    Accepted = 4  # source address specified, accepted connection, loop running

    Connecting = 5  # source and destination address specified, in handshake
    Connected = 6  # source and destination address specified, loop running

    Closed = 7


class Socket:
    def __init__(self, controller):
        self.controller = controller
        self.state = State.Zero

        # defined in bind call
        self.source_ip = None
        self.source_port = None

        # can be undefined in case of listening socket
        self.destination_ip = None
        self.destination_port = None

        # received, not processed packets
        self.received_packets: typing.List[TCPPacket] = []
        self.received_packets_condition = threading.Condition()

        # listen
        self.backlog = 0

        self.seq = None
        self.ack = None
        self.window = 10
        self.remote_ack = None

        # message to send
        self.pending_data = bytes()
        self.pending_data_condition = threading.Condition()
        self.received_data = bytes()
        self.received_data_condition = threading.Condition()

        self._thread = threading.Thread(target=self.run)
        self._lock = threading.Lock()

    def run(self):
        while not self.controller.check_off():
            # sleep for timeout or incoming packets
            with self.received_packets_condition:
                self.received_packets_condition.wait(timeout=ACK_TIMEOUT)

            with self._lock:
                for packet in self.received_packets:
                    # update ack id
                    if packet.has_flags("ack"):
                        self.ack = max(self.ack, packet.ack)
                    elif packet.has_flags("rst"):
                        break
                    else:
                        # receive data
                        message = packet.payload
                        self.received_data += message

                        # send ack for received data
                        ack_packet = TCPPacket(
                            source_ip=self.source_ip,
                            destination_ip=self.destination_ip,
                            source_port=self.source_port,
                            destination_port=self.destination_port,
                            seq=self.seq,
                            ack=packet.seq,
                            payload=bytes()
                        )
                        ack_packet.flag_ack = 1
                        self.remote_ack = packet.seq  # TODO algorithm
                        self.controller.send_packet(ack_packet)

                        # unblock recv call
                        with self.received_data_condition:
                            self.received_data_condition.notify_all()

                self.received_packets = []

                # send pending data:
                with self.pending_data_condition:
                    while len(self.pending_data) > 0 and self.ack == self.seq:
                        message = self.pending_data[:MSS]
                        self.pending_data = self.pending_data[MSS:]
                        self.pending_data_condition.notify_all()

                        send_packet = TCPPacket(
                            source_ip=self.source_ip,
                            destination_ip=self.destination_ip,
                            source_port=self.source_port,
                            destination_port=self.destination_port,
                            seq=self.seq + len(message),
                            ack=self.remote_ack,
                            payload=message
                        )
                        self.seq += len(message)
                        self.controller.send_packet(send_packet)

    def process(self, packet: TCPPacket):
        with self.received_packets_condition:
            with self._lock:
                if self.state == State.Listening and len(self.received_packets) > self.backlog:
                    return
                self.received_packets.append(packet)
                self.received_packets_condition.notify_all()

    def bind(self, ip, port):
        with self._lock:
            self.controller.bind(self, ip, port, None, None)
            self.state = State.Binded
            self.source_ip = ip
            self.source_port = port

    def listen(self, backlog: int = 1024):
        with self._lock:
            assert self.state == State.Binded, "listen on not binded socket"
            self.state = State.Listening
            self.backlog = backlog

    def accept(self):
        with self._lock:
            assert self.state == State.Listening
        # get first syn packet
        while True:
            self._lock.acquire()
            if len(self.received_packets) > 0:
                syn_packet = self.received_packets[0]
                self.received_packets = self.received_packets[1:]
                if syn_packet.has_only_flags("syn"):
                    break
            self._lock.release()
        self._lock.release()

        # create socket and set state
        socket = Socket(self.controller)
        socket.state = State.Accepting
        self.controller.bind(socket, self.source_ip, self.source_port,
                             syn_packet.source_ip, syn_packet.source_port)
        socket.source_ip = self.source_ip
        socket.source_port = self.source_port
        socket.destination_ip = syn_packet.source_ip
        socket.destination_port = syn_packet.source_port

        # send syn ack packet
        syn_ack_packet = TCPPacket(
            source_ip=self.source_ip,
            destination_ip=syn_packet.source_ip,
            source_port=self.source_port,
            destination_port=syn_packet.source_port,
            seq=1,
            ack=syn_packet.seq + 1,
            payload=bytes()
        )
        syn_ack_packet.flag_syn = 1
        syn_ack_packet.flag_ack = 1
        socket.seq, socket.ack = 1, 0
        socket.remote_ack = syn_packet.seq + 1
        self.controller.send_packet(syn_ack_packet)

        # wait ack packet
        while True:
            socket._lock.acquire()
            if len(socket.received_packets) > 0:
                ack_packet = socket.received_packets[0]
                socket.received_packets = socket.received_packets[1:]
                if ack_packet.has_only_flags("ack"):
                    break
            socket._lock.release()
        socket._lock.release()

        socket._thread.start()
        return socket

    def send(self, data: bytes):
        with self.pending_data_condition:
            self.pending_data = data
            while True:
                self.pending_data_condition.wait()
                if len(self.pending_data) == 0:
                    return

    def recv(self, buffer_size=65536):
        with self.received_data_condition:
            while True:
                self.received_data_condition.wait()
                if len(self.received_data) > 0:
                    break
            buffer = self.received_data[:buffer_size]
            self.received_data = self.received_data[buffer_size:]
            return buffer

    def connect(self, destination_ip, destination_port):
        with self._lock:
            # configure
            assert self.state == State.Binded, "connect on not binded socket"
            self.state = State.Connecting
            self.controller.unbind(self.source_ip, self.source_port, None, None)
            self.controller.bind(self, self.source_ip, self.source_port, destination_ip, destination_port)
            self.destination_ip, self.destination_port = destination_ip, destination_port
            self.seq, self.ack = 1, 0

            # send syn packet
            syn_packet = TCPPacket(source_ip=self.source_ip,
                                   source_port=self.source_port,
                                   destination_ip=self.destination_ip,
                                   destination_port=self.destination_port,
                                   seq=1, ack=0, payload=bytes())
            syn_packet.flag_syn = 1
            self.controller.send_packet(syn_packet)

        # wait for response packet
        with self.received_packets_condition:
            while len(self.received_packets) == 0:
                self.received_packets_condition.wait()

        # process response
        with self._lock:
            assert len(self.received_packets) == 1
            syn_ack_packet: TCPPacket = self.received_packets.pop()
            assert syn_ack_packet.has_only_flags("syn", "ack") and syn_ack_packet.ack == syn_packet.seq + 1
            self.seq, self.ack = syn_ack_packet.ack, syn_ack_packet.ack
            self.remote_ack = syn_ack_packet.seq + 1

            # send ack packet
            ack_packet = TCPPacket(
                source_ip=self.source_ip,
                destination_ip=self.destination_ip,
                source_port=self.source_port,
                destination_port=self.destination_port,
                seq=syn_packet.seq + 1,
                ack=syn_ack_packet.seq + 1,
                payload=bytes()
            )
            ack_packet.flag_ack = 1
            self.controller.send_packet(ack_packet)

            # update state and start processing cycle
            self.state = State.Connected
            self._thread.start()

    def close(self):
        with self._lock:
            self.controller.unbind(self.source_ip, self.source_port, self.destination_ip, self.destination_port)
            is_alive = self.state == State.Connected or self.state == State.Accepted
            self.state = State.Closed
        if is_alive:
            self._thread.join()
