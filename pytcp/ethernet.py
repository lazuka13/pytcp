import binascii
import struct

ETH_P_IP = 0x0800
ETH_P_ALL = 3


def chunks(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


class EthernetPacket:
    def __init__(self, source_mac, destination_mac, protocol, payload: bytes):
        self.source_mac = source_mac
        self.destination_mac = destination_mac
        self.protocol = protocol
        self.payload = payload

    def serialize(self):
        return struct.pack(
            "!6s6sH",
            binascii.unhexlify(self.destination_mac.replace(":", "")),
            binascii.unhexlify(self.source_mac.replace(":", "")),
            self.protocol) + self.payload

    @staticmethod
    def deserialize(data: bytes):
        unpacked = struct.unpack("!6s6sH", data[:14])
        destination_mac, source_mac, protocol = unpacked
        source_mac = ':'.join(chunks(binascii.hexlify(source_mac).decode(), 2))
        destination_mac = ':'.join(chunks(binascii.hexlify(destination_mac).decode(), 2))
        obj = EthernetPacket(source_mac=source_mac, destination_mac=destination_mac,
                             protocol=protocol, payload=data[14:])
        return obj
