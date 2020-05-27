import socket
import struct


class IPPacket:
    SERIALIZE = '!BBHHHBBH4s4s'

    def __init__(self, source_ip_addr: str, destination_ip_addr: str, payload: bytes):
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
        self.total_length = 20 + len(payload)
        self.identification = 0  # not used
        # flags
        self.flag_reserved = 0
        self.flag_dont_fragment = 1  # set DF flag
        self.flag_more_fragments = 0
        self.fragment_offset = 0  # not used

        self.ttl = 255  # disable ttl
        self.protocol = socket.IPPROTO_TCP  # payload == TCP packet
        self.header_checksum = 0  # TODO add header_checksum calculation and validation
        self.source_ip_addr = source_ip_addr  # set in build() or parse()
        self.destination_ip_addr = destination_ip_addr  # set in build() or parse()
        # no options
        self.payload = payload

    def serialize(self):
        return struct.pack(
            IPPacket.SERIALIZE,
            (self.version << 4) + self.internet_header_length,
            self.dscp,
            self.total_length,
            self.identification,
            (self.flag_reserved << 15) + (self.flag_dont_fragment << 14) +
            (self.flag_more_fragments << 13) + self.fragment_offset,
            self.ttl,
            self.protocol,
            self.header_checksum,
            socket.inet_aton(self.source_ip_addr),
            socket.inet_aton(self.destination_ip_addr)
        ) + self.payload

    @staticmethod
    def deserialize(payload: bytes):
        unpacked = struct.unpack(IPPacket.SERIALIZE, payload[:20])
        version_header_length, dscp, total_length = unpacked[0:3]
        version = version_header_length >> 4
        internet_header_length = version_header_length - (version << 4)
        identification, flags = unpacked[3:5]
        flag_reserved = (flags >> 15) & 1
        flag_dont_fragment = (flags >> 14) & 1
        flag_more_fragments = (flags >> 13) & 1
        ttl, protocol, header_checksum = unpacked[5:8]
        source_ip_addr = socket.inet_ntoa(unpacked[8])
        destination_ip_addr = socket.inet_ntoa(unpacked[9])
        obj = IPPacket(source_ip_addr=source_ip_addr, destination_ip_addr=destination_ip_addr,
                       payload=payload[20:total_length])
        obj.version = version
        obj.internet_header_length = internet_header_length
        obj.identification = identification
        obj.flag_reserved = flag_reserved
        obj.flag_dont_fragment = flag_dont_fragment
        obj.flag_more_fragments = flag_more_fragments
        obj.ttl = ttl
        obj.protocol = protocol
        obj.header_checksum = header_checksum
        return obj
