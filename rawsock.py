import signal
import socket
import struct
import ipaddress
import time
import ctypes, os
import threading
from typing import Any, Callable, Tuple


class NATLease:
    expires: int  # when lease should be removed

    proto: int

    source_saddr: ipaddress._IPAddressBase
    source_daddr: ipaddress._IPAddressBase
    # source_sport: int
    # source_dport: int

    target_saddr: ipaddress._IPAddressBase
    target_daddr: ipaddress._IPAddressBase
    # source_sport: int
    # source_dport: int

    def __init__(
        self,
        lease_time: float,
        source_saddr: ipaddress._IPAddressBase,
        source_daddr: ipaddress._IPAddressBase,
        target_saddr: ipaddress._IPAddressBase,
        target_daddr: ipaddress._IPAddressBase,
        proto=-1,
    ) -> None:
        self.expires = time.time() + lease_time

        self.source_saddr = source_saddr
        self.source_daddr = source_daddr
        self.target_saddr = target_saddr
        self.target_daddr = target_daddr

        self.proto = proto


class NATAddressPool:
    MAX_SIZE = 10

    pool: list[ipaddress._BaseAddress]  # just pre-compute addresses in the beginning
    used: set[int]  # associative array containing indices of the used addresses

    def __init__(self, network: ipaddress.IPv4Network) -> None:
        self.pool = []
        self.used = set()

        hosts = network.hosts()

        while len(self.pool) < NATAddressPool.MAX_SIZE:
            try:
                self.pool.append(next(hosts))
            except StopIteration:
                break

    def pick(self) -> ipaddress._BaseAddress:
        for idx in range(len(self.pool)):
            if not idx in self.used:
                self.used.add(idx)
                return self.pool[idx]
        else:
            raise "pool empty"

    def drop(self, address: ipaddress._BaseAddress):
        for idx in range(len(self.pool)):
            if (
                self.pool[idx] == address
            ):  # idk if this compares objects or actually compares the address
                self.used.remove(idx)
                return

    def full(self) -> bool:
        return len(self.used) >= len(self.pool)


class NATManager:
    LEASE_TIME = 2 * 60  # 2 minutes

    TARGET_DADDRv4 = ipaddress.IPv4Address(
        "127.0.0.1"
    )  # only communicate on local host for now
    # TARGET_DADDRv6 = ipaddress.IPv6Address("::1") # only communicate on local host for now

    leases: list[NATLease]
    pool4: NATAddressPool

    def __init__(self, network4=ipaddress.IPv4Network("127.48.0.0/16")) -> None:
        self.leases = []
        self.pool4 = NATAddressPool(network4)

    def lease(
        self,
        saddr: ipaddress._IPAddressBase,
        daddr: ipaddress._IPAddressBase,
        proto=-1,
    ) -> NATLease:

        if not isinstance(saddr, ipaddress.IPv4Address) or not isinstance(
            daddr, ipaddress.IPv4Address
        ):
            raise ValueError

        current_time = time.time()

        # create lease
        target_saddr = self.pool4.pick()

        newlease = NATLease(
            NATManager.LEASE_TIME,
            saddr,
            daddr,
            target_saddr,
            NATManager.TARGET_DADDRv4,
            proto=proto,
        )

        for idx, _lease in enumerate(self.leases):
            if _lease.expires < current_time:
                self.pool4.drop(_lease.target_saddr)
                self.leases[idx] = newlease
                return self.leases[idx]
        else:
            self.leases.append(newlease)
            return self.leases[-1]

    def get_lease(
        self,
        target_saddr: ipaddress._BaseAddress,
        target_daddr: ipaddress._BaseAddress,
        proto=-1,
    ):
        # NAT were to smarter request more information and do the checking
        for lease in self.leases:
            if (
                lease.target_saddr == target_saddr
                and lease.target_daddr == target_daddr
                and (lease.proto < 0 or lease.proto == proto)
            ):
                return lease


natman = NATManager()


def is_admin():
    try:
        return os.getuid() == 0
    except AttributeError:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False


# https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/if_ether.h
# define ETH_P_ALL	0x0003		/* Every packet (be careful!!!) */
# define ETH_P_IP	0x0800		/* Internet Protocol packet	*/
# define ETH_P_IPV6	0x86DD		/* IPv6 over bluebook		*/

ETH_P_ALL = 0x3
ETH_P_IP = 0x0800

STRUCT_IPHDR_FORMAT = "!BBHHHBBHII"


def read_datahdr(
    ethertype: int, data: bytes
) -> Tuple[int, ipaddress._BaseAddress, ipaddress._BaseAddress]:
    if ethertype == ETH_P_IP:
        values = struct.unpack(STRUCT_IPHDR_FORMAT, data[:20])
        proto = values[6]
        saddr = ipaddress.IPv4Address(values[8])
        daddr = ipaddress.IPv4Address(values[9])
    else:
        raise ValueError

    return (proto, saddr, daddr)


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


def replace_ip4addres(
    data: bytes, saddr: ipaddress.IPv4Address, daddr: ipaddress.IPv4Address
):
    data = bytearray(data)

    set_bytes(data, bytes(2), 10)
    set_bytes(data, saddr.packed, 12)
    set_bytes(data, daddr.packed, 16)

    # calculate checksum
    # do not know if this is wrong just uses give ihl value
    set_bytes(
        data,
        bytes_from_number(calculate_checksum(data[: (data[0] & 0x0F) << 2]), 2),
        10,
    )

    return bytes(data)


class RawSock:
    """
    The class that communicates through the server host
    The assumption is that if you send something, youre expected receive a reply to the same address
    """

    natman: NATManager

    # (NATLease, transactionid, input_function)
    transactions: list[Tuple[NATLease, int, Callable[[int, bytes, int], None]]]
    raw_socket_listener_flag = True

    def __init__(self) -> None:
        self.natman = NATManager()
        self.transactions = []

        self.setup_raw_socket_listeners()
        self.setup_raw_socket_senders()

    def setup_raw_socket_senders(self):
        if not is_admin():
            raise PermissionError("You MUST run this script as root")

        self.sock_sender = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW
        )
        # self.sock_sender.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    def setup_raw_socket_listeners(self):
        if not is_admin():
            raise PermissionError("You MUST run this script as root")

        # TODO: abstract listening socket and make it work for windows aswell
        ### ONLY WORKS ON LINUX
        # https://docs.python.org/3/library/socket.html
        sock_listener = socket.socket(
            socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(ETH_P_ALL)
        )

        # spin up another thread

        thread = threading.Thread(
            None, self.raw_socket_listener, args=(sock_listener,), daemon=True
        )
        thread.start()

    def raw_socket_listener(self, sock: socket.socket):
        if not is_admin():
            return

        while self.raw_socket_listener_flag:
            b, addr = sock.recvfrom(2**16)

            if addr[1] != ETH_P_IP:  # only support IPv4 for now
                continue
            if addr[2] == socket.PACKET_OUTGOING:
                continue  # idk

            # read iphdr
            proto, saddr, daddr = read_datahdr(addr[1], b)

            lease = self.natman.get_lease(
                daddr, saddr, proto=proto
            )  # flipped because this is the receipt of a packet

            if not lease:
                continue

            # TODO: replace the source and destination and recalculate checksum

            data = replace_ip4addres(b, lease.source_daddr, lease.source_saddr)
            
            # get transaction
            for transaction in self.transactions:
                if transaction[0] != lease:
                    continue

                print(f"replying to: {hex(transaction[1])},  with a pakcket")
                transaction[2](addr[1], data, transaction[1])
                
                self.kill_transaction(transaction[1], lease)
                self.natman.leases.remove(lease)


    def kill_transaction(self, transactionid: int, lease: NATLease):
        # remove transaction from transactions
        for i, transaction in enumerate(self.transactions):
            if transaction[0] == transactionid and transaction[1] == lease:
                self.transactions.pop(i)
                return

    def output(
        self,
        ethertype: int,
        data: bytes,
        transactionid: int,
        input: Callable[[int, bytes, int], None],
    ) -> Callable:
        """input takes the data and outputs stuff"""  # HMM might need more informatin but will go with this blind interface

        if ethertype != ETH_P_IP:
            return
        if len(data) < 20:
            return

        # parse iphdr
        proto, saddr, daddr = read_datahdr(ethertype, data)

        # obtain lease
        lease = self.natman.lease(saddr, daddr, proto)

        transaction = (lease, transactionid, input)

        # modify ip packet header

        print(
            lease.source_saddr,
            lease.source_daddr,
            lease.target_saddr,
            lease.target_daddr,
        )

        data = replace_ip4addres(data, lease.target_saddr, lease.target_daddr)
        # output the packet but that is for another day.
        self.sock_sender.sendto(data, (str(lease.target_daddr), 0))

        # finally return a function that closes the transaction

        self.transactions.append(transaction)
        return lambda: self.kill_transaction(transactionid, lease)


if __name__ == "__main__":
    # rawsock = RawSock()
    # for testing close the listening thread because otherwise i is annoying
    # time.sleep(10)
    # rawsock.raw_socket_listener_flag = False

    d = b"\x45\x00\x00\x22\xc5\x19\x00\x00\x40\x11\xb7\x7f\x7f\x30\x00\x01\x7f\x00\x00\x01\x0e\x38\x27\x1b\x00\x0e\x77\x2f\xc0\xa8\x01\x0a\x0e\x38"
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

    e = s.sendto(d, ("127.0.0.1", 0))
    print(e)
