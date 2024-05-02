import ctypes
import os
from typing import Literal


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


class logger:
    @staticmethod
    def log(message, t: Literal["ERROR", "INFO", "WARN", "SUCCESS"]):
        color_prefix = ""
        symbol = "-"
        if t == "ERR":
            color_prefix = "\033[31m"
            symbol = "%"
        elif t == "WARN":
            symbol = "/"
            color_prefix = "\033[33m"
        elif t == "SUCCESS":
            symbol = "\\"
            color_prefix = "\033[32m"

        print(f"{color_prefix}[{symbol}]\033[0m {message}")

    @staticmethod
    def err(message: str):
        return logger.log(message, "ERR")

    @staticmethod
    def warn(message: str):
        return logger.log(message, "WARN")

    @staticmethod
    def success(message: str):
        return logger.log(message, "SUCCESS")

    @staticmethod
    def info(message: str):
        return logger.log(message, "INFO")


if __name__ == "__main__":
    logger.err("ooops")
    logger.warn("warning")
    logger.info("info")
