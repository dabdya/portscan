from helptools import check_pack
from time import perf_counter
import socket
import abc


class IScanner(abc.ABC):
    """"Scanner interface"""
    def __init__(self, ip, timeout, packs_id, packs):
        super().__init__()
        self._timeout = timeout
        self._packs_id = packs_id
        self._packs = packs
        self._ip = ip

    @abc.abstractmethod
    def _process_proto(self, proto, port):
        """Must return tuple (TCP|UDP, port, time, proto)"""
        pass

    def scan(self, port):
        results = dict()
        socket.setdefaulttimeout(self._timeout)
        for proto in self._packs:
            result = self._process_proto(proto, port)
            if not result:
                continue
            if (result[1], result[-1]) not in results:
                results[result[1], result[-1]] = result
        return results


class ConnectedTCPScanner(IScanner):
    """Simple connected TCP scanner"""
    def __init__(self, ip, timeout, packs_id, packs):
        super().__init__(ip, timeout, packs_id, packs)

    def _process_proto(self, proto, port):
        """Return TCP port time proto"""
        with socket.socket(
                socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                start_time = perf_counter()
                sock.connect((self._ip, port))
                sock.sendall(self._packs[proto])
                data = sock.recv(12)
                data = check_pack(
                    data, self._packs_id, self._packs[proto])
                end_time = perf_counter() - start_time
                if data:
                    return "TCP", port, end_time, data
            except socket.timeout as error:
                pass


class SynTCPScanner(IScanner):
    """SYN TCP scanner"""
    def __init__(self, ip, timeout, packs_id, packs):
        super().__init__(ip, timeout, packs_id, packs)

    def _process_proto(self, proto, port):
        pass


class UDPScanner(IScanner):
    """Simple UDP scanner"""
    def __init__(self, ip, timeout, packs_id, packs):
        super().__init__(ip, timeout, packs_id, packs)

    def _process_proto(self, proto, port):
        """Return UDP port time proto"""
        with socket.socket(
                socket.AF_INET, socket.SOCK_DGRAM) as sock:
            try:
                start_time = perf_counter()
                address = (self._ip, port)
                sock.sendto(self._packs[proto], address)
                data, _ = sock.recvfrom(1024)
                data = check_pack(
                    data, self._packs_id, self._packs[proto])
                end_time = perf_counter() - start_time
                if data:
                    return "UDP", port, end_time, data
            except socket.timeout as error:
                pass
