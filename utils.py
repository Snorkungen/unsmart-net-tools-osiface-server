import ctypes
import os


def is_admin():
    try:
        return os.getuid() == 0
    except AttributeError:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False


def calculate_checksum(buf: bytes) -> int:
    i = 0
    length = len(buf)
    sum = 0

    while length > 1:
        data = ((buf[i] << 8) & 0xFF00) | ((buf[i + 1]) & 0xFF)
        sum += data

        if (sum & 0xFFFF0000) > 0:
            sum = sum & 0xFFFF
            sum += 1

        i += 2
        length -= 2

    if length > 0:
        sum += buf[i] << 8 & 0xFF00
        if (sum & 0xFFFF0000) > 0:
            sum = sum & 0xFFFF
            sum += 1

    sum = ~sum
    sum = sum & 0xFFFF
    return sum


def set_bytes(d: bytearray, b: bytes, offset: int):
    for i in range(len(b)):
        d[offset + i] = b[i]


def bytes_from_number(n: int, l=1):
    if not n:
        return bytes(len)

    a = []
    a.append(n & 255)
    while n >= 256:
        n = n >> 8
        a.append(n & 255)

    a.reverse()
    b = bytearray(l)

    diff = len(b) - len(a)
    if diff < 0:
        raise ValueError(diff)

    set_bytes(b, a, diff)

    return bytes(b)
