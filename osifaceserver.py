import json
import struct
from typing import Any, Literal, Union
from ioengine import IOEngineFactory, NATManager
from utils import *
import wsserver

"""
    osiface packet protocol header BIG_ENDIAN

    version         - 2-Bytes   0x1
    opcode          - 2-Bytes
    clientid        - 4-bytes
    transactionid   - 4-bytes 

    pad/ethertype   - 2-bytes

    data            - 1486-bytes
"""

"""
    NOTE: this servers communication is not reliable
"""

OSIFS_VERSION = 1
OSIFS_OP_INIT = 1
OSIFS_OP_REPLY = 2
OSIFS_OP_FETCH_CLIENTS = 3
OSIFS_OP_SEND_PACKET = 8

natman = NATManager({"10.1.1.40": ("127.0.0.1", "127.48.0.0/16")})
ioengine_factory = IOEngineFactory(natman)


def get_server_configuration_options() -> dict:
    destinations = [str(k) for k in natman.source_daddr_lookup_table]

    return {"destinations": destinations}


class OSIFSFrame:
    version: int
    opcode: int
    clientid: int
    transactionid: int
    ethertype: int

    data: bytes

    def __init__(
        self,
        data: Union[
            Any,
            bytes,
            dict[
                Literal[
                    "version",
                    "opcode",
                    "clientid",
                    "transactionid",
                    "ethertype",
                    "data",
                    "options",
                ],
                Any,
            ],
        ],
    ) -> None:
        if isinstance(data, OSIFSFrame):
            self.version = data.version
            self.opcode = data.opcode
            self.clientid = data.clientid
            self.transactionid = data.transactionid
            self.ethertype = data.ethertype
            self.data = bytes(data.data)  # an attempt at a copy
        elif isinstance(data, bytes) or isinstance(data, bytearray):
            self.__init__bytes(data)
        elif isinstance(data, dict):
            self.__init__dict(data)
        else:
            raise ValueError

    def __init__dict(
        self,
        data: dict[
            Literal[
                "version",
                "opcode",
                "clientid",
                "transactionid",
                "ethertype",
                "data",
                "options",
            ],
            Any,
        ],
    ):
        self.version = data["version"]
        self.opcode = data["opcode"]
        self.clientid = data["clientid"]
        self.transactionid = data["transactionid"]
        self.ethertype = data["ethertype"]

        if data["data"]:
            self.data = data["data"]
        elif data["options"]:
            self.set_options(data["options"])

    def __init__bytes(self, data: bytes):
        header = struct.unpack("!HHLLH", data[:14])

        self.version = header[0]
        self.opcode = header[1]
        self.clientid = header[2]
        self.transactionid = header[3]
        self.ethertype = header[4]

        self.data = data[14:]

    def options(self):
        if self.opcode == 0 or self.opcode > 0x7 or len(self.data) < 2:
            return {}

        return json.loads(self.data)  # let json raise problems if there are any

    def set_options(self, options: dict):
        self.data = bytes(json.dumps(options, separators=(",", ":")), "utf-8")

    def serialize(self) -> bytes:
        buf = struct.pack(
            f"!HHLLH{len(self.data)}s",
            self.version,
            self.opcode,
            self.clientid,
            self.transactionid,
            self.ethertype,
            self.data,
        )

        return buf


class OSIFSClient:
    wsconn: wsserver.WSConn
    clientid: int
    options: dict

    transaction_killers = []

    is_alive = True  # thsis is just a hint that there might be a situation where the client is left a zombie

    # support udp4 first for the vibes

    def __init__(self, wsconn: wsserver.WSConn, clientid: int, options: dict) -> None:
        self.wsconn = wsconn
        self.clientid = clientid

        self.options = options

    # the following bottom two methods might no be helpful

    def input(self, ethertype: int, data: bytes, transactionid: int):
        """forward data to client using wsconn"""

        logger.success(
            f"sending packet, ett: {ethertype:#x}, cid: {self.clientid:#x}, xid: {transactionid:#x}"
        )

        frame = OSIFSFrame(
            {
                "version": OSIFS_VERSION,
                "opcode": OSIFS_OP_SEND_PACKET,
                "clientid": self.clientid,
                "transactionid": transactionid,
                "ethertype": ethertype,
                "data": data,
            }
        )

        return self.wsconn.send(frame.serialize())

    def output(self, ethertype: int, data: bytes, transactionid: int):
        """receive a packet and output it using the raw socket"""
        # what would be the interaction between RawSock and this

        ioengine = ioengine_factory.make(ethertype, data)

        self.transaction_killers.append(
            ioengine.output(
                ethertype,
                data,
                lambda et, d: self.input(et, d, transactionid),
                clientid=self.clientid,
            )
        )

    def close(self):
        for k in self.transaction_killers:
            k()
        self.wsconn.close()


class OSIFServer:
    clients: list[OSIFSClient] = []
    clientid = 0

    server: wsserver.WSServer

    def __init__(self, saddr="0.0.0.0", port=7000) -> None:
        self.server = wsserver.WSServer((saddr, port))

    def run(self):
        self.server.onreceive(self.handle_receive)
        self.server.onclose(self.handle_close)
        self.server.serve_forever()  # serve_forever is blocking
        # to do check if this thing would be capable of supporting stuff i.e raw socket requires
        # admin privileges
        return

    def handle_receive(self, wsconn: wsserver.WSConn, data: bytes):
        frame = OSIFSFrame(data)
        # read frame
        if frame.version != OSIFS_VERSION:
            return

        if frame.opcode == OSIFS_OP_INIT:
            # initialize a client
            self.handle_receive_initialize_client(wsconn, frame)
        elif frame.opcode == OSIFS_OP_FETCH_CLIENTS:
            self.handle_receive_fetch_clients(wsconn, frame)
        elif frame.opcode == OSIFS_OP_SEND_PACKET:
            self.handle_receive_packet(wsconn, frame)

    def handle_receive_initialize_client(
        self, wsconn: wsserver.WSConn, frame: OSIFSFrame
    ):
        options = frame.options()
        client: OSIFSClient = None

        if not client:
            # create a HWSClient
            self.clientid = 1 + self.clientid * 3
            client = OSIFSClient(
                wsconn,
                self.clientid,
                {
                    **options,
                },
            )

            self.clients.append(client)

        response_frame = OSIFSFrame(frame)
        response_frame.version = OSIFS_VERSION
        response_frame.opcode = OSIFS_OP_REPLY
        response_frame.clientid = client.clientid

        response_frame.set_options(
            {**get_server_configuration_options(), **client.options}
        )

        wsconn.send(response_frame.serialize())
        logger.info(
            f"client initialised, cid: {client.clientid:#x}, xid: {frame.transactionid:#x}"
        )

    def handle_receive_fetch_clients(self, wsconn, frame):
        response_frame = OSIFSFrame(frame)
        response_frame.opcode = OSIFS_OP_REPLY
        response_frame.set_options(
            {
                "data": list(
                    map(
                        lambda client: {
                            "clientid": client.clientid,
                            "peer": client.wsconn.request.getpeername(),
                            "options": client.options,
                        },
                        self.clients,
                    )
                )
            }
        )

        wsconn.send(response_frame.serialize())

    def handle_receive_packet(self, wsconn: wsserver.WSConn, frame: OSIFSFrame):
        # first mision is to get the client
        client: OSIFSClient = None
        for i in range(len(self.clients)):
            if (
                self.clients[i].clientid == frame.clientid
                and self.clients[i].wsconn == wsconn
            ):
                client = self.clients[i]
                break
        if not client:
            logger.err(
                f"handle packet cid: {frame.clientid:#x}, xid: {frame.transactionid:#x}"
            )
            return

        logger.info(
            f"received packet, ett: {frame.ethertype:#x}, cid: {frame.clientid:#x}, xid: {frame.transactionid:#x}"
        )

        ethertype_ipv4 = 0x0800
        if ethertype_ipv4 == frame.ethertype:
            client.output(frame.ethertype, frame.data, frame.transactionid)


    def handle_close(self, wsconn: wsserver.WSConn):
        # find client call teardown method and remove client from list

        i = 0
        while i < len(self.clients):
            # how is the comaparison going to be made
            # client id ? primary
            # wsconn secondary
            if self.clients[i].wsconn != wsconn:
                i += 1
                continue

            logger.info(f"closing client, cid: {hex(self.clients[i].clientid)}")
            self.clients[i].close()
            self.clients.pop(i)


server = OSIFServer()
ioengine_factory.start()

logger.warn(OSIFServer.__name__ + " Server running")
server.run()
