import socket
import struct
import ipaddress
import time
from utils import *
import threading
from typing import Any, Callable, Optional, Tuple


class NATLease:
    expires: int  # when lease should be removed
    clientid: int = None  # value for tying leases to the same client

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
        clientid: int = None,
    ) -> None:
        self.expires = time.time() + lease_time

        self.source_saddr = source_saddr
        self.source_daddr = source_daddr
        self.target_saddr = target_saddr
        self.target_daddr = target_daddr

        self.proto = proto

        self.clientid = clientid


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
            if self.pool[idx] == address and (
                idx in self.used  # prevent KeyError
            ):  # idk if this compares objects or actually compares the address
                self.used.remove(idx)
                return

    def full(self) -> bool:
        return len(self.used) >= len(self.pool)


class NATManager:
    LEASE_TIME = 40  # 40 seconds

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
        # start of kwargs
        clientid: int = None,
    ) -> Optional[NATLease]:
        """
            clientid is for allowing the reuse of an target_saddr, but still returns a new lease
            only returns a lease if a destination is found
        """

        if not isinstance(saddr, ipaddress.IPv4Address) or not isinstance(
            daddr, ipaddress.IPv4Address
        ):
            raise ValueError

        current_time = time.time()

        target_saddr: ipaddress._BaseAddress = None

        # check if client already has a target_saddr
        if clientid:
            for _lease in self.leases:
                if _lease.clientid == clientid:
                    target_saddr = _lease.target_saddr
                    break

        if not target_saddr:
            target_saddr = self.pool4.pick()

        # create lease
        newlease = NATLease(
            NATManager.LEASE_TIME,
            saddr,
            daddr,
            target_saddr,
            NATManager.TARGET_DADDRv4,
            proto=proto,
            clientid=clientid,
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
                (lease.proto < 0 or lease.proto == proto)
                and lease.target_saddr == target_saddr
                and lease.target_daddr == target_daddr
            ):
                return lease

    def remove(self, lease: NATLease):
        self.pool4.drop(lease.target_saddr)
        self.leases.remove(lease)
        pass


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


def replace_ip4address(
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


# TODO: circumvent the fact that the loopback routine does not play nice with raw ip sockets
class IOEngine:
    """Base class for communication with the operating system, that handles threading"""

    socket_listener_flag = False
    thread: threading.Thread = None

    def start_listening(self) -> None:
        if self.thread and self.thread.is_alive():
            return  # thread is already running

        # somehow setup threading for a function
        self.socket_listener_flag = True

        self.thread = threading.Thread(None, self.listen_forever, daemon=True)
        self.thread.start()

    def listen_forever(self):
        while self.socket_listener_flag:
            self.process_incoming()

    def process_incoming(self):
        """This method gets called forever untill program ends"""
        pass

    def terminate_transaction(self, ident: Any):
        pass

    def output(
        self,
        ethertype: int,
        data: bytes,
        input: Callable[
            [int, bytes], None
        ],  # transaction id has to be bound to input method
        clientid: int = None,
    ) -> Callable:
        """
        Output using the operating system, and do some NAT things

        """
        return lambda: self.terminate_transaction(None)


class RawIPv4IOEngine(IOEngine):
    natman: NATManager
    transactions: list[Tuple[NATLease, Callable[[int, bytes], None]]]

    def __init__(self, natman: NATManager = NATManager(), self_start=True) -> None:
        self.natman = natman
        self.transactions = []

        # bind socket to send ip packets including header
        self.send_socket = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW
        )

        # bind socket to receive all ip packets
        self.listen_socket = socket.socket(
            socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(ETH_P_IP)
        )

        if self_start:
            self.start_listening()

    def process_incoming(self):
        b, addr = self.listen_socket.recvfrom(2**16)

        if addr[1] != ETH_P_IP:  # only support IPv4 for now
            return
        if addr[2] == socket.PACKET_OUTGOING:
            return  # idk

        # read iphdr
        proto, saddr, daddr = read_datahdr(addr[1], b)
        lease = self.natman.get_lease(
            daddr, saddr, proto=proto
        )  # flipped because this is the receipt of a packet

        if not lease:
            return

        # spin up another thread that then finishes the pro
        return threading.Thread(
            None,
            self.process_incoming2,
            args=(
                b,
                addr,
                lease,
            ),
            daemon=True,
        ).start()

    def process_incoming2(self, b: bytes, addr, lease: NATLease):
        data = replace_ip4address(b, lease.source_daddr, lease.source_saddr)
        print(
            "I should be replying but something is going wrong", len(self.transactions)
        )
        # get transaction
        for transaction in self.transactions:
            if transaction[0] != lease:
                continue

            transaction[1](addr[1], data)
            # just accept the fact that zombie transaction will exist untill the client terminates the transaction
            # i do not know what i'm doing, it works but i do not like how it works
            self.terminate_transaction(lease)

    def terminate_transaction(self, lease: NATLease):
        for i, transaction in enumerate(self.transactions):
            if transaction[0] == lease:
                self.transactions.pop(i)
                self.natman.remove(lease)
                return

    def output(
        self,
        ethertype: int,
        data: bytes,
        input: Callable[[int, bytes], None],
        clientid: int = None,
    ) -> Callable[..., Any]:
        if ethertype != ETH_P_IP:
            return

        if len(data) < 20:
            return

        # parse iphdr
        proto, saddr, daddr = read_datahdr(ethertype, data)
        # obtain lease
        lease = self.natman.lease(saddr, daddr, proto, clientid=clientid)

        if not lease:
            return lambda: None # no lease found, silently quit 

        transaction = (lease, input)

        data = replace_ip4address(data, lease.target_saddr, lease.target_daddr)
        # output the packet but that is for another day.

        self.send_socket.sendto(data, (str(lease.target_daddr), 0))
        self.transactions.append(transaction)

        print(
            [(l.clientid, str(l.target_saddr), l.expires) for l in self.natman.leases]
        )

        return lambda: self.terminate_transaction(lease)


class IOEngineFactory:
    """Singleton that gives the users the ability the get an engine"""

    useless_engine = IOEngine()
    raw_ip_engine = RawIPv4IOEngine(self_start=False)

    @staticmethod
    def make(ethertype: int, data: bytes) -> IOEngine:
        if ethertype == 0x0800:
            return IOEngineFactory.raw_ip_engine

        return IOEngineFactory.useless_engine

    @staticmethod
    def start():
        IOEngineFactory.raw_ip_engine.start_listening()


if __name__ == "__main__":
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
    print("receiving")
    b, addr = s.recvfrom(100)
    print(b, addr)
