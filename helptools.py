from re import match
import struct


def check_pack(pack, pack_id, was_send):
    """Determines what type of package came"""
    smtp_pattern = b"[0-9]{3}"
    if pack[:4].startswith(b"HTTP"):
        return "HTTP"
    elif struct.pack("!H", pack_id) in pack:
        return "DNS"
    elif match(smtp_pattern, pack[:3]):
        return "SMTP"
    elif was_send == pack:
        return "ECHO"
    elif pack.startswith(b"+"):
        return "POP3"
    else:
        try:
            struct.unpack('!BBBb11I', pack)
        except struct.error as err:
            return
        return "NTP"


def check_ip(ip_address):
    """Check IP address"""
    octets = list(map(int, ip_address.split(".")))
    return len(octets) == 4 \
        and max(octets) < 256 and min(octets) > - 1


def _check_proto(proto):
    """Checks format of proto argument"""
    pattern = r"^(tcp|udp)/((\d+,)|(\d+\-\d+,))+$"
    mo = match(pattern, proto + ",")
    if not mo:
        pattern = r"^(tcp|udp)$"
        mo = match(pattern, proto)
        return mo is not None

    ranges = mo.string[:-1].split("/")[1].split(",")
    for _range in ranges:
        _range = _range.split("-")
        if len(_range) == 1 and int(_range[0]) > 65535:
            return False
        elif len(_range) == 2:
            if int(_range[0]) >= int(_range[1]) \
                    or int(max(_range)) > 65535:
                return False
    return True


def process_proto(proto):
    """Return tuple of tcp_ports and udp_ports"""
    full_range = list(range(1, 65536))
    result = {"udp": [], "tcp": []}
    if not proto:
        return full_range, full_range

    for _proto in proto:
        if not _check_proto(_proto):
            raise TypeError("Invalid proto format")

        _proto = _proto.split("/")
        if len(_proto) == 1:
            result[_proto[0]] = full_range
        else:
            for _range in _proto[1].split(","):
                if "-" not in _range:
                    result[_proto[0]] += [int(_range)]
                else:
                    _range = _range.split("-")
                    _range = list(range(
                        int(_range[0]),
                        int(_range[1]) + 1))
                    result[_proto[0]] += _range

    return result["udp"], result["tcp"]
