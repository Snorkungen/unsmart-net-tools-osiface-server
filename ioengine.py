import socket
import struct
import ipaddress
import time
from utils import *
import threading
from typing import Any, Callable, Optional, Tuple, Union

import platform

assert platform.system() == "Linux", "This program only supports linux socket API"


class NATLease:
    expires: int  # when lease should be removed
    clientid: int = None  # value for tying leases to the same client

    proto: int

    source_saddr: ipaddress._IPAddressBase
    source_daddr: ipaddress._IPAddressBase
    source_sport: int
    source_dport: int

    target_saddr: ipaddress._IPAddressBase
    target_daddr: ipaddress._IPAddressBase
    target_sport: int
    target_dport: int

    def __init__(
        self,
        lease_time: float,
        source_saddr: ipaddress._IPAddressBase,
        source_daddr: ipaddress._IPAddressBase,
        target_saddr: ipaddress._IPAddressBase,
        target_daddr: ipaddress._IPAddressBase,
        proto=-1,
        source_sport: int = -1,
        source_dport: int = -1,
        target_sport: int = -1,
        target_dport: int = -1,
        clientid: int = None,
    ) -> None:
        self.expires = time.time() + lease_time

        self.source_saddr = source_saddr
        self.source_daddr = source_daddr
        self.target_saddr = target_saddr
        self.target_daddr = target_daddr

        self.proto = proto

        self.source_sport = source_sport
        self.source_dport = source_dport
        self.target_sport = target_sport
        self.target_dport = target_dport

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
    source_port: int

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
        self.source_port = 1800

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

    def create_lease(
        self,
        saddr: ipaddress._IPAddressBase,
        daddr: ipaddress._IPAddressBase,
        proto=-1,
        sport: int = -1,
        dport: int = -1,
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

        target_saddr: ipaddress._BaseAddress
        target_daddr, pool = self.source_daddr_lookup_table[daddr]

        # first look if there already is a lease that is for the same client
        # and has the same relevant details
        if clientid:
            for existing_lease in self.leases:
                if existing_lease.clientid != clientid:
                    continue
                elif (
                    # check that the source addresses are equal
                    existing_lease.source_saddr == saddr
                    and existing_lease.source_daddr == daddr
                    # check that if proto set that they are equal
                    # check the source port numbers
                    and (existing_lease.proto < 0 or existing_lease.proto == proto)
                    and (
                        existing_lease.source_sport < 0
                        or existing_lease.source_sport == sport
                    )
                    and (
                        existing_lease.source_dport < 0
                        or existing_lease.source_dport == dport
                    )
                ):
                    # update expiry time
                    existing_lease.expires += self.LEASE_TIME
                    return existing_lease

        """
            For future pondering, is there actually a good reason as to why
            target_saddr needs to be unique per transaction,
            there would'nt be that large of a rework, if the discrimination
            would be handled by the client.

            I think the best option would be prefer to give each transaction a unique
            target_saddr, but if that is not possible revert to then sharing addresses.
        """

        target_sport = sport

        if proto > 0 and sport > 0 and dport > 0:
            # Now the lease is responsible for and can touch the mess with the "sport"

            # get a target source address i.e. the address that the output is going to use
            target_saddr = pool.pick(enforce_unique=False)
            # get a sport number
            self.source_port += 1
            target_sport = self.source_port

        if not target_saddr:
            if pool.empty():
                print(pool.used, "Pool is empty", pool.network)
                return None  # there should be some kind of recovery logic here

            target_saddr = pool.pick(enforce_unique=True)

        # create lease
        newlease = NATLease(
            lease_time=NATManager.LEASE_TIME,
            source_saddr=saddr,
            source_daddr=daddr,
            target_saddr=target_saddr,
            target_daddr=target_daddr,
            proto=proto,
            # just for now just pass on the ports without any thought
            source_sport=sport,
            source_dport=dport,
            target_sport=target_sport,
            target_dport=dport,
            clientid=clientid,
        )

        self.leases.append(newlease)
        return self.leases[-1]

    def get_matching_leases(
        self,
        target_saddr: ipaddress._BaseAddress,
        target_daddr: ipaddress._BaseAddress,
        proto=-1,
        target_sport: int = -1,
        target_dport: int = -1,
    ):

        for existing_lease in self.leases:
            if (
                # check that the source addresses are equal
                existing_lease.target_saddr == target_saddr
                and existing_lease.target_daddr == target_daddr
                # check that if proto set that they are equal
                # check the target port numbers
                and (existing_lease.proto < 0 or existing_lease.proto == proto)
                and (
                    existing_lease.target_sport < 0
                    or existing_lease.target_sport == target_sport
                )
                and (
                    existing_lease.target_dport < 0
                    or existing_lease.target_dport == target_dport
                )
            ):
                yield existing_lease

    def remove(self, lease: NATLease, modify_leases=True):
        # get the pool from the lookup table
        _, pool = self.source_daddr_lookup_table[lease.source_daddr]
        pool.drop(lease.target_saddr)

        if modify_leases and lease in self.leases:
            self.leases.remove(lease)


# https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/if_ether.h
# define ETH_P_ALL	0x0003		/* Every packet (be careful!!!) */
# define ETH_P_IP	0x0800		/* Internet Protocol packet	*/
# define ETH_P_IPV6	0x86DD		/* IPv6 over bluebook		*/

ETH_P_ALL = 0x3
ETH_P_IP = 0x0800

STRUCT_IP_PSEUDOHDR_FORMAT = "!IIBBH"
STRUCT_IPHDR_FORMAT = "!BBHHHBBHII"
STRUCT_UPDHDR_FORMAT = "!HHHH"


def read_datahdr(
    ethertype: int, data: bytes
) -> Tuple[
    int, ipaddress._BaseAddress, ipaddress._BaseAddress, Optional[int], Optional[int]
]:
    offset = 0
    if ethertype == ETH_P_IP:
        values = struct.unpack(STRUCT_IPHDR_FORMAT, data[:20])
        proto = values[6]
        saddr = ipaddress.IPv4Address(values[8])
        daddr = ipaddress.IPv4Address(values[9])

        offset = (values[0] & 0x0F) << 2
    else:
        raise ValueError

    sport = -1
    dport = -1

    if proto == socket.IPPROTO_UDP:
        values = struct.unpack_from(STRUCT_UPDHDR_FORMAT, data, offset)
        sport = values[0]
        dport = values[1]

    return (proto, saddr, daddr, sport, dport)


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


def replace_udp4_info(data: bytes, offset: int, sport: int, dport: int) -> bytearray:
    data = bytearray(data)

    # read the udp header
    udp_values = struct.unpack_from(STRUCT_UPDHDR_FORMAT, data, offset)
    udp_values = list(udp_values)

    udp_values[0] = sport  # replace the source port
    udp_values[1] = dport  # replace the source port
    udp_values[3] = 0  # set the checksum field to zero

    # write into the udp header some values
    struct.pack_into(STRUCT_UPDHDR_FORMAT, data, offset, *udp_values)

    proto, saddr, daddr, *_ = read_datahdr(ETH_P_IP, data)
    # create pseudo header
    pseudo_header = struct.pack(
        STRUCT_IP_PSEUDOHDR_FORMAT,
        int(daddr),
        int(saddr),
        0,
        proto,
        udp_values[2],  # the udp header lenght
    )
    csum = calculate_checksum(
        bytes([*pseudo_header, *data[offset : offset + udp_values[2]]])
    )
    # write the calculated checksum into the data
    struct.pack_into("!H", data, offset + 6, (csum or 0xFFFF))

    return data


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
    transactions: list[Tuple[NATLease, Callable[[int, bytes], None]]] = []

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

        # spin up another thread that to do the processing of the incoming packet
        return threading.Thread(
            None,
            self.process_incoming2,
            args=(b, addr),
            daemon=True,
        ).start()

    def process_incoming2(self, b: bytes, addr):
        # read iphdr
        proto, saddr, daddr, sport, dport = read_datahdr(addr[1], b)

        for lease in self.natman.get_matching_leases(
            target_saddr=daddr,
            target_daddr=saddr,
            proto=proto,
            target_sport=dport,
            target_dport=sport,
        ):
            data = replace_ip4address(b, lease.source_daddr, lease.source_saddr)

            # TODO: replace ports if they're defined
            # modify the incoming packet data
            if lease.proto > 0 and lease.target_sport > 0 and lease.target_dport > 0:
                if lease.proto == socket.IPPROTO_UDP:
                    udp_begin = (
                        data[0] & 0xF
                    ) << 2  # assume the ip header is the first thing so read the offset, and assume it is correct

                    data = replace_udp4_info(
                        data, udp_begin, lease.source_dport, lease.source_sport
                    )

            for transaction in self.transactions:
                if transaction[0] != lease:
                    continue

                transaction[1](addr[1], data)

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
        proto, saddr, daddr, sport, dport = read_datahdr(ethertype, data)
        # obtain lease
        lease = self.natman.create_lease(
            saddr, daddr, proto, sport=sport, dport=dport, clientid=clientid
        )

        if not lease:
            logger.err(f"failed to send packet, no NATLease found for {daddr}")
            return lambda: None  # no lease found, silently quit

        self.transaction_add(lease, input)

        data = replace_ip4address(data, lease.target_saddr, lease.target_daddr)

        if lease.proto > 0 and lease.target_sport > 0 and lease.target_dport > 0:
            # do some additional processing for the outgoing packet

            if lease.proto == socket.IPPROTO_UDP:
                udp_begin = (
                    data[0] & 0xF
                ) << 2  # assume the ip header is the first thing so read the offset, and assume it is correct

                data = replace_udp4_info(
                    data, udp_begin, lease.target_sport, lease.target_dport
                )

        self.send_socket.sendto(data, (str(lease.target_daddr), 0))

        return lambda: self.transaction_remove(lease)

    def transaction_add(self, lease: NATLease, input: Callable[[int, bytes], None]):
        # okay here the goal is to have as few transactions as possible

        for idx, transaction in enumerate(self.transactions):
            if (
                lease != transaction[0]
            ):  # it is the natmans responsibility to reduce the number of leases created
                continue

            # update input function otherwise return
            self.transactions[idx] = (lease, input)
            return

        self.transactions.append((lease, input))

    def transaction_remove(self, lease: NATLease):
        # NOTE: an issue is that when the OSIFSClient closes
        # it calls this function for every output it has created
        # not actually a serious problem, so ignore for now
        for i, transaction in enumerate(self.transactions):
            if transaction[0] == lease:
                self.transactions.pop(i)
                self.natman.remove(lease)


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
    # fmt: off
    iphdr = bytes([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x45, 0x00,
            0x00, 0x2c, 0x08, 0xe4, 0x40, 0x00, 0x40, 0x11, 0x33, 0xdb, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00,
            0x00, 0x01, 0x8a, 0xd7, 0x27, 0x1b, 0x00, 0x18, 0xfe, 0x2b, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20,
            0x55, 0x44, 0x50, 0x20, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72
        ])[14:]

    values = read_datahdr(0x800, iphdr)
    print(values)
