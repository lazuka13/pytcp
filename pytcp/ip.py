import socket
import struct


class IPPacket:
    SERIALIZE = '!BBHHHBBH4s4s'

    def __init__(self):
        """
        Basic IPPacket class
        No options support - so ip_internet_header_length is fixed to 5
        """
        self.version = 4  # fixed version
        self.internet_header_length = 5
        # 1 byte in total, 4 bits for each field
        dscp = 0  # leaving default value
        ecn = 0  # not supported
        self.dscp = (dscp << 2) + ecn
        # total length is in bytes, header = 20 bytes + len(payload)
        self.total_length = 20
        self.identification = 0  # not used
        # flags
        self.flag_reserved = 0
        self.flag_dont_fragment = 1  # set DF flag
        self.flag_more_fragments = 0
        self.fragment_offset = 0  # not used

        self.ttl = 255  # disable ttl
        self.protocol = socket.IPPROTO_TCP  # payload == TCP packet
        self.header_checksum = 0  # TODO add header_checksum calculation and validation
        self.source_ip_addr = None  # set in build() or parse()
        self.destination_ip_addr = None  # set in build() or parse()
        # no options
        self.payload = bytes()

        # for validation
        self.is_built = False

    def build(self, source: str, destination: str, payload: bytes):
        assert not self.is_built
        self.source_ip_addr = socket.inet_aton(source)
        self.destination_ip_addr = socket.inet_aton(destination)
        self.payload = payload
        self.total_length += len(payload)

        # for validation
        self.is_built = True

    def serialize(self):
        assert self.is_built
        return struct.pack(
            IPPacket.SERIALIZE,
            (self.version << 4) + self.internet_header_length,
            self.dscp,
            self.total_length,
            self.identification,
            (self.flag_reserved << 7) + (self.flag_dont_fragment << 6) +
            (self.flag_more_fragments << 5) + self.fragment_offset,
            self.ttl,
            self.protocol,
            self.header_checksum,
            self.source_ip_addr,
            self.destination_ip_addr
        ) + self.payload

    @staticmethod
    def deserialize(payload: bytes):
        obj = IPPacket()
        unpacked = struct.unpack(IPPacket.SERIALIZE, payload[:20])
        version_header_length, obj.dscp, obj.total_length = unpacked[0:3]
        obj.version = version_header_length >> 4
        obj.internet_header_length = version_header_length - (obj.version << 4)
        obj.identification, flags = unpacked[3:5]
        obj.flag_reserved = (flags >> 7) & 1
        obj.flag_dont_fragment = (flags >> 6) & 1
        obj.flag_more_fragments = (flags >> 5) & 1
        obj.ttl, obj.protocol, obj.header_checksum = unpacked[5:8]
        obj.source_ip_addr = unpacked[8]
        obj.destination_ip_addr = unpacked[9]
        if obj.total_length > 20:
            obj.payload = payload[20:obj.total_length]
        return obj

    def dict(self):
        return {
            "type": "IP",
            "version": self.version,
            "internet_header_length": self.internet_header_length,  # should be 5
            "dscp": self.dscp,
            "total_length": self.total_length,
            "identification": self.identification,
            "flag_reserved": self.flag_reserved,
            "flag_dont_fragment": self.flag_dont_fragment,
            "flag_more_fragments": self.flag_more_fragments,
            "ttl": self.ttl,
            "protocol": self.protocol,
            "header_checksum": self.header_checksum,
            "source_ip_addr": socket.inet_ntoa(self.source_ip_addr),
            "destination_ip_addr": socket.inet_ntoa(self.destination_ip_addr),
            "payload": self.payload.decode(),
        }
