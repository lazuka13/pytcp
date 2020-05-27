import socket
import struct


def build_checksum(message):
    s = 0
    for i in range(0, len(message), 2):
        a, b = message[i], message[i + 1]
        s = s + (a + (b << 8))
    s = s + (s >> 16)
    s = ~s & 0xffff
    return s


class TCPPacket:
    SERIALIZE = "!HHLLBBHHH"

    def __init__(self, source_port: int, destination_port: int, source_ip: str,
                 destination_ip: str, seq: int, ack: int, payload: bytes):
        self.source_port = source_port
        self.destination_port = destination_port
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.seq, self.ack = seq, ack

        self.data_offset = 160  # no options support

        # flags (all zero by default)
        self.flag_rsv = (0 << 9)
        self.flag_noc = (0 << 8)
        self.flag_cwr = (0 << 7)
        self.flag_ecn = (0 << 6)
        self.flag_urg = (0 << 5)
        self.flag_ack = (0 << 4)
        self.flag_psh = (0 << 3)
        self.flag_rst = (0 << 2)
        self.flag_syn = (1 << 1)
        self.flag_fin = 0

        self.window_size = socket.htons(5840)  # TODO define
        self.checksum = 0  # set in parse or build
        self.urgent_point = 0  # not supported

        self.payload = payload

    def serialize_flags(self):
        return self.flag_rsv + self.flag_noc + self.flag_cwr + \
               self.flag_ecn + self.flag_urg + self.flag_ack + \
               self.flag_psh + self.flag_rst + self.flag_syn + self.flag_fin

    def deserialize_flags(self, flags):
        self.flag_rsv = (flags >> 9) & 1
        self.flag_noc = (flags >> 8) & 1
        self.flag_cwr = (flags >> 7) & 1
        self.flag_ecn = (flags >> 6) & 1
        self.flag_urg = (flags >> 5) & 1
        self.flag_ack = (flags >> 4) & 1
        self.flag_psh = (flags >> 3) & 1
        self.flag_rst = (flags >> 2) & 1
        self.flag_syn = (flags >> 1) & 1
        self.flag_fin = flags & 1

    def _serialize(self, checksum):
        return struct.pack(self.SERIALIZE, self.source_port, self.destination_port,
                           self.seq, self.ack, self.data_offset, self.serialize_flags(),
                           self.window_size, checksum, self.urgent_point)

    def serialize(self):
        self.checksum = self.calculate_checksum()
        return self._serialize(self.checksum) + self.payload

    def calculate_checksum(self):
        _serialized = self._serialize(0)
        pseudo_header = struct.pack('!4s4sHH', socket.inet_aton(self.source_ip), socket.inet_aton(self.destination_ip),
                                    socket.IPPROTO_TCP, len(_serialized) + len(self.payload))
        total = pseudo_header + _serialized + self.payload
        return build_checksum(total)

    def validate_checksum(self):
        if self.calculate_checksum() != self.checksum:
            return False
        return True

    @staticmethod
    def deserialize(source_ip: str, destination_ip: str, payload: bytes):
        """
        We need to know source_ip and destination_ip for checksum validation
        :param source_ip: ip of packet creator
        :param destination_ip: ip of packet destination
        :param payload: packet data
        :return: constructed TCP packet
        """
        unpacked = struct.unpack(TCPPacket.SERIALIZE, payload[:20])
        source_port, destination_port = unpacked[0:2]
        seq, ack = unpacked[2], unpacked[3]
        data_offset, flags, window_size = unpacked[4:7]  # TODO: parse flags
        checksum, urgent_point = unpacked[7], unpacked[8]
        payload = payload[int(data_offset / 8):]
        obj = TCPPacket(source_port=source_port, destination_port=destination_port,
                        source_ip=source_ip, destination_ip=destination_ip, seq=seq, ack=ack, payload=payload)
        obj.data_offset = data_offset
        obj.window_size = window_size
        obj.checksum = checksum
        obj.urgent_point = urgent_point
        obj.deserialize_flags(flags)
        obj.validate_checksum()
        return obj

    def dict(self):
        return {
            "type": "TCP",
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "seq": self.seq,
            "ack": self.ack,
            "data_offset": self.data_offset,
            "window_size": self.window_size,
            "checksum": self.checksum,
            "urgent_point": self.urgent_point,
        }
