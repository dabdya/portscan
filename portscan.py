from multiprocessing import Pool
from random import randint
import struct
import sys

REQUIREMENT_ERROR = -1
INVALID_IP_ERROR = -2
INVALID_PROTO_ERROR = -3

try:
    from scanners import IScanner, ConnectedTCPScanner, UDPScanner
    from helptools import check_ip, process_proto
    from argparser import create_argparser
except (ImportError, ModuleNotFoundError):
    sys.stdout.write("Requirement modules not found")
    sys.exit(REQUIREMENT_ERROR)


ID = randint(1, 65535)
DNS_PACK = struct.pack("!HHHHHH", ID, 256, 1, 0, 0, 0)
DNS_PACK += b"\x06google\x03com\x00\x00\x01\x00\x01"

TCP_PACKS = {
    "HTTP": b"GET / HTTP/1.1\r\nHost: google.com\r\n\r\n",
    "DNS": struct.pack("!H", len(DNS_PACK)) + DNS_PACK,
    "SMTP": b"message",
    "ECHO": b"ping",
    "POP3": b"auth"
}

UDP_PACKS = {
    "DNS": DNS_PACK,
    "ECHO": b"ping",
    "NTP": ('\x1b' + 47 * '\0').encode('utf-8')
}


class PortScanner:
    """Port scanner with data parallelism"""
    def __init__(self, num_threads, v=False, g=False):
        self._pool = Pool(num_threads)
        self.verbose = v
        self.guess = g

    def start(self, scanner, ports):
        if not isinstance(scanner, IScanner):
            raise TypeError("Invalid scanner")
        if len(ports) == 0:
            return
        results = self._pool.imap(scanner.scan, ports)
        self._process_result(results)

    def _process_result(self, results):
        while True:
            try:
                nxt = results.next()
                for res in nxt:
                    answer = f"{nxt[res][0]} {nxt[res][1]}"
                    if self.verbose:
                        answer += f" {nxt[res][2]}ms"
                    if self.guess:
                        answer += f" {nxt[res][3]}"
                    sys.stdout.write(answer + "\n")
            except (ConnectionResetError, StopIteration) as error:
                break


def main():
    args = create_argparser().parse_args()
    if not check_ip(args.IP_ADDRESS):
        sys.stdout.write("Invalid IP")
        sys.exit(INVALID_IP_ERROR)

    try:
        udp_ports, tcp_ports = process_proto(args.proto)
    except TypeError as error:
        sys.stdout.write(str(error))
        sys.exit(INVALID_PROTO_ERROR)

    portscan = PortScanner(
        num_threads=args.num_threads, v=args.verbose, g=args.guess)

    tcp_scanner = ConnectedTCPScanner(
        args.IP_ADDRESS, args.timeout, ID, TCP_PACKS)
    portscan.start(tcp_scanner, tcp_ports)

    udp_scanner = UDPScanner(
        args.IP_ADDRESS, args.timeout, ID, UDP_PACKS)
    portscan.start(udp_scanner, udp_ports)


if __name__ == "__main__":
    main()
