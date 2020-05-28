from scapy.layers.l2 import getmacbyip
from scapy.route import Route

if __name__ == '__main__':
    print(getmacbyip("127.0.0.1"))
    print(Route().route("127.0.0.1"))
