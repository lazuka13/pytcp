import enum
import threading

from pytcp.tcp import TCPPacket


class State(enum.Enum):
    Zero = 0  # uninitialized
    Binded = 1  # source address specified

    Listening = 2  # source address specified, listening socket, loop running
    Accepting = 3  # source address specified, accepting connection
    Accepted = 4  # source address specified, accepted connection, loop running

    Connecting = 5  # source and destination address specified, in handshake
    Connected = 6  # source and destination address specified, loop running


class Socket:
    def __init__(self, controller):
        self.controller = controller
        self.state = State.Zero

        self.source_ip = None
        self.source_port = None

        self.destination_ip = None
        self.destination_port = None

        # received, not processed packets
        self.received_packets = None
        self.received_packets_condition = threading.Condition()

        # message to send
        self.pending_data = bytes()
        self.pending_data_condition = threading.Condition()
        self.received_data = bytes()
        self.received_data_condition = threading.Condition()

        self.__thread = threading.Thread(target=self.run(), args=(self,))
        self.__lock = threading.Lock()

    def run(self):
        while not self.controller.check_off():
            ack_timeout = 0.05
            # sleep for ack timeout OR packet receive
            self.received_packets_condition.wait(timeout=ack_timeout)
            with self.__lock:
                if self.state == State.Listening:
                    pass
                    # process listen (create sockets)
                elif self.state == State.Connected or self.state == State.Accepted:
                    pass
                    # process Connected
                else:
                    pass

    def process(self, packet: TCPPacket):
        with self.__lock:
            self.received_packets.append(packet)
            self.received_packets_condition.notify_all()

    def bind(self, ip, port):
        with self.__lock:
            self.controller.bind(self, ip, port)
            self.state = State.Binded
            self.source_ip = ip
            self.source_port = port

    def listen(self):
        with self.__lock:
            assert self.state == State.Binded, "listen on not binded socket"
            self.state = State.Listening

    def accept(self):
        pass

    def send(self, data: bytes):
        with self.__lock:
            self.pending_data = data
        while True:
            # check data was sent
            with self.__lock:
                if len(self.pending_data) == 0:
                    break
            self.pending_data_condition.wait(timeout=0.05)

    def recv(self):
        while True:
            # check data was received
            with self.__lock:
                if len(self.received_data) > 0:
                    to_return = self.received_data
                    self.received_data = bytes()
                    return to_return
            self.received_data_condition.wait(timeout=0.05)

    def connect(self, destination_ip, destination_port):
        self.__lock.acquire()

        assert self.state == State.Binded, "connect on not binded socket"
        self.state = State.Connecting
        self.controller.unbind(self.source_ip, self.source_port, None, None)
        self.controller.bind(self.source_ip, self.source_port, destination_ip, destination_port)
        self.destination_ip = destination_ip
        self.destination_port = destination_port

        # send syn packet
        syn_packet = TCPPacket(
            source_ip=self.source_ip,
            destination_ip=self.destination_ip,
            source_port=self.source_port,
            destination_port=self.destination_ip,
            seq=0, ack=0, payload=bytes()
        )
        syn_packet.flag_syn = 1
        self.controller.send_packet(syn_packet)

        # wait response
        while len(self.received_packets) == 0:
            self.__lock.release()
            self.received_packets_condition.wait()  # todo: add timeout
            self.__lock.acquire()

        # process response
        assert len(self.received_packets) == 1, "incorrect amount of response packets"
        syn_ack_packet: TCPPacket = self.received_packets[0]
        self.received_packets = []
        assert syn_ack_packet.flag_ack == 1 and \
               syn_ack_packet.flag_syn == 1 and \
               syn_ack_packet.ack == syn_packet.seq + 1, "incorrect handshake response received"

        # send ack packet
        ack_packet = TCPPacket(
            source_ip=self.source_ip,
            destination_ip=self.destination_ip,
            source_port=self.source_port,
            destination_port=self.destination_ip,
            seq=syn_packet.seq + 1,
            ack=0,
            payload=bytes()
        )
        syn_packet.flag_ack = 1
        self.controller.send_packet(ack_packet)

        # update state and start processing cycle
        self.state = State.Connected
        self.__thread.run()
        self.__lock.release()

    def close(self):
        pass
