import socket
import struct
import ipaddress
import time
from utils import *
import threading
from typing import Any, Callable, Optional, Tuple, Union


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

    references: list[int]
    """
    references is a one to one maping, the possible values for each index are:
    0: address is unused free and available
    -1: address is used and the picker requires the address is unique
    1,2,3...: how many references there are for the address
    """

    network: ipaddress.IPv4Network

    def __init__(self, network: ipaddress.IPv4Network) -> None:
        self.network = network
        self.pool = []
        hosts = network.hosts()

        if isinstance(hosts, list):
            # edge case where there is only one possible host
            self.pool.extend(hosts)
        else:
            while len(self.pool) < NATAddressPool.MAX_SIZE:
                try:
                    self.pool.append(next(hosts))
                except StopIteration:
                    break

        self.references = [0] * len(self.pool)

    def pick(self, enforce_unique=True) -> ipaddress._BaseAddress:
        """Pick an address from the pool of available addresses

        Args:
            enforce_unique -- flag if the chosen address needs to be unique (default True)
        """
        for idx in range(len(self.pool)):
            reference_count = self.references[idx]
            if (not enforce_unique and reference_count < 0) or (
                enforce_unique and reference_count != 0
            ):
                continue
            elif enforce_unique and reference_count == 0:
                self.references[idx] = -1
                return self.pool[idx]

            # if not enforcing unique choose the first available

            self.references[idx] += 1
            return self.pool[idx]
        else:
            raise Exception("pool empty")

    def drop(self, address: ipaddress._BaseAddress):
        """Drop a address from the pool, and make the address available for future use

        Args:
            address -- address to be dropped
        """

        for idx in range(len(self.pool)):
            if self.pool[idx] != address:
                continue
            if self.references[idx] < 0:
                self.references[idx] = 0
            elif self.references[idx] > 0:
                self.references[idx] -= 1

    def empty(self, enforce_unique=True) -> bool:
        try:
            a = self.pick(enforce_unique=enforce_unique)
            self.drop(a)
            return False
        except:
            return True


class NATManager:
    LEASE_TIME = 40  # 40 seconds
    leases: list[NATLease]

    def __init__(
        self,
        natmap: dict[
            Union[str, ipaddress._BaseAddress],
            Tuple[
                Union[str, ipaddress._BaseAddress], Union[str, ipaddress._BaseNetwork]
            ],
        ] = {},
    ) -> None:
        self.leases = []

        # just use a map
        self.source_daddr_lookup_table: dict[
            ipaddress._BaseAddress, Tuple[ipaddress._BaseAddress, NATAddressPool]
        ] = {}

        # popluate source_daddr_lookup_table
        for source_daddr in natmap:
            target_daddr, target_saddr_network = natmap[source_daddr]
            source_daddr, value = NATManager._create_source_daddr_lookup_table_value(
                self.source_daddr_lookup_table,
                source_daddr,
                target_daddr,
                target_saddr_network,
            )

            self.source_daddr_lookup_table[source_daddr] = value

        self.leases = []
        self.pool4 = NATAddressPool(ipaddress.IPv4Network("127.48.0.0/16"))

    @staticmethod
    def _create_source_daddr_lookup_table_value(
        lookup_table: dict[
            ipaddress._BaseAddress, Tuple[ipaddress._BaseAddress, NATAddressPool]
        ],
        source_daddr: Union[str, ipaddress._BaseAddress],
        target_daddr: Union[str, ipaddress._BaseAddress],
        target_saddr_network: Union[str, ipaddress._BaseNetwork],
    ) -> Tuple[ipaddress._BaseAddress, Tuple[ipaddress._BaseAddress, NATAddressPool]]:
        # first assume we're using an ipv4 address
        try:
            source_daddr = ipaddress.IPv4Address(source_daddr)
            target_daddr = ipaddress.IPv4Address(target_daddr)
            target_saddr_network = ipaddress.IPv4Network(
                target_saddr_network
            )  # let NetmaskValueError bubble up
        except ipaddress.AddressValueError:
            # allow errors to bubble up
            source_daddr = ipaddress.IPv6Address(source_daddr)
            target_daddr = ipaddress.IPv6Address(target_daddr)
            target_saddr_network = ipaddress.IPv6Network(target_saddr_network)

        # disallow multiple of the same source_daddr

        if source_daddr in lookup_table:
            raise ValueError(source_daddr, "appears in natmap more than once")

        return source_daddr, (target_daddr, NATAddressPool(target_saddr_network))

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

        if not daddr in self.source_daddr_lookup_table:
            return None  # failed to find the destination

        current_time = time.time()
        target_saddr: ipaddress._BaseAddress = None
        target_daddr, pool = self.source_daddr_lookup_table[daddr]

        # check if client already has a target_saddr
        if clientid:
            for _lease in self.leases:
                if _lease.clientid == clientid:
                    target_saddr = _lease.target_saddr
                    break

        if pool.empty():
            print(pool.used, "Pool is empty", pool.network)
            return None  # there should be some kind of recovery logic here

        if not target_saddr:
            target_saddr = pool.pick()

        # create lease
        newlease = NATLease(
            NATManager.LEASE_TIME,
            saddr,
            daddr,
            target_saddr,
            target_daddr,
            proto=proto,
            clientid=clientid,
        )

        for idx, _lease in enumerate(self.leases):
            if _lease.expires < current_time:
                # here the issue in what pool is this
                self.remove(_lease, modify_leases=False)
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

    def remove(self, lease: NATLease, modify_leases=True):
        # get the pool from the lookup table
        _, pool = self.source_daddr_lookup_table[lease.source_daddr]
        pool.drop(lease.target_saddr)

        if modify_leases:
            self.leases.remove(lease)


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

        self.setup()

        # somehow setup threading for a function
        self.socket_listener_flag = True

        self.thread = threading.Thread(None, self.listen_forever, daemon=True)
        self.thread.start()

    def setup(self) -> None:
        pass

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

    def __init__(self, natman: NATManager = None, self_start=True) -> None:
        self.natman = natman
        self.transactions = []

        if self_start:
            self.start_listening()

    def setup(self) -> None:
        # bind socket to send ip packets including header
        self.send_socket = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW
        )

        # bind socket to receive all ip packets
        self.listen_socket = socket.socket(
            socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(ETH_P_IP)
        )

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
            return lambda: None  # no lease found, silently quit

        transaction = (lease, input)

        data = replace_ip4address(data, lease.target_saddr, lease.target_daddr)
        # output the packet but that is for another day.

        self.send_socket.sendto(data, (str(lease.target_daddr), 0))
        self.transactions.append(transaction)

        return lambda: self.terminate_transaction(lease)


class IOEngineFactory:
    natman: NATManager
    useless_engine: IOEngine
    raw_ip_engine: RawIPv4IOEngine

    def __init__(self, natman: NATManager) -> None:
        self.natman = natman
        self.useless_engine = IOEngine()
        self.raw_ip_engine = RawIPv4IOEngine(self.natman, self_start=False)
        pass

    def make(self, ethertype: int, data: bytes) -> IOEngine:
        if ethertype == 0x0800:
            return self.raw_ip_engine

        return self.useless_engine

    def start(self):
        self.raw_ip_engine.start_listening()


if __name__ == "__main__":
    natpool = NATAddressPool(ipaddress.IPv4Network("192.168.1.12/30"))

    print(natpool.pool, natpool.references)

    a = natpool.pick(enforce_unique=False)
    natpool.drop(a)
    print(natpool.pool, natpool.references)

    print(natpool.pick(enforce_unique=False))
    print(natpool.pick(enforce_unique=False))
    print(natpool.pick(enforce_unique=True))
    print(natpool.pick(enforce_unique=False))
    print(natpool.pick(enforce_unique=True))

    print(natpool.pool, natpool.references)

