import socketserver
import socket
import base64
import hashlib
import struct
from typing import Any, Callable, Tuple

# https://www.rfc-editor.org/rfc/rfc6455

rhh_method = "__method"
rhh_url = "__url"
rhh_proto = "__proto_version"


def read_http_headers(data: bytes) -> dict[str, str]:
    headers = {}

    lines = data.split(b"\r\n")

    first_line = lines[0]

    params = first_line.split(b" ")
    if len(params) != 3:
        raise ValueError
    headers[rhh_method] = params[0].strip().decode("ascii")
    headers[rhh_url] = params[1].strip().decode("ascii")
    headers[rhh_proto] = params[2].strip().decode("ascii")

    for line in lines[1:]:
        line = line.strip()

        if len(line) <= 0:
            continue

        key, value = line.split(b":", 1)
        headers[key.strip().decode("ascii")] = value.strip().decode("ascii")

    return headers


class WSConn:
    request: socket.socket

    def __init__(self, request: socket.socket) -> None:
        self.request = request

    def send(self, data: bytes):
        len_bytes = [len(data)]
        if len(data) > 125:
            if len(data) > 2**16:
                len_bytes = [127, *struct.pack("!q", len(data))]
            else:
                len_bytes = [126, *struct.pack("!H", len(data))]

        self.request.send(bytearray([0x82, *len_bytes, *data]))

    def close(self):
        # TOOD: send websocket close
        # close tcp socket
        pass


class WSServer(socketserver.ThreadingTCPServer):
    def __init__(
        self,
        server_address: Tuple[str | bytes | bytearray | int],
        bind_and_activate: bool = True,
    ) -> None:
        self.allow_reuse_address = True
        super().__init__(server_address, WSRequestHandler, bind_and_activate)

    data: bytes

    handlers_connect = []
    handlers_close = []
    handlers_receive = []

    def dispatch_connect(self, conn: WSConn):
        for f in self.handlers_connect:
            f(conn)

    def dispatch_receive(self, conn: WSConn, data: bytes):
        for f in self.handlers_receive:
            f(conn, data)

    def dispatch_close(self, conn: WSConn):
        for f in self.handlers_close:
            f(conn)

    def onconnect(self, f: Callable[[WSConn], None]):
        self.handlers_connect.append(f)

    def onclose(self, f: Callable[[WSConn], None]):
        self.handlers_close.append(f)

    def onreceive(self, f: Callable[[WSConn, bytes], None]):
        self.handlers_receive.append(f)


WSRequest_CLOSED = -1
WSRequest_UNINIT = 0
WSRequest_CONNECTED = 1

WS_MAGIC = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class WSFrame:
    def __init__(self, data: bytes) -> None:
        if len(data) < 2:
            raise ValueError

        data_offset = 2
        header = struct.unpack("!BB", data[:data_offset])

        self.fin = bool(header[0] & 0x80)

        self.rsv1 = bool(header[0] & (0x80 >> 1))
        self.rsv2 = bool(header[0] & (0x80 >> 2))
        self.rsv3 = bool(header[0] & (0x80 >> 3))

        self.opcode = header[0] & 0x0F

        self.mask = bool(header[1] & 0x80)

        self.payload_length = header[1] & 0x7F

        if self.payload_length == 126:
            header = struct.unpack("!H", data[data_offset : data_offset + 2])
            self.payload_length = header[0]
            data_offset = data_offset + 2
        elif self.payload_length == 127:
            header = struct.unpack("!q", data[data_offset : data_offset + 8])
            self.payload_length = header[0]

            if self.payload_length < 0:
                raise ValueError

            data_offset = data_offset + 8

        if self.mask:
            # unmask data
            masking_key = data[data_offset : data_offset + 4]
            data_offset += 4

            self.data = bytearray(data[data_offset:])

            for i in range(len(self.data)):
                self.data[i] = self.data[i] ^ masking_key[i % 4]
        else:
            self.data = bytearray(data[data_offset:])


class WSRequestHandler(socketserver.BaseRequestHandler):
    request: socket.socket
    server: WSServer
    wsconn: WSConn = None
    state: int = WSRequest_UNINIT
    data: bytes

    def handle(self) -> None:
        while self.state >= 0:
            self.data = self.request.recv(2**16)  # Memory is cheap

            if len(self.data) == 0:
                continue

            if self.state == WSRequest_UNINIT:
                self.handle_uninit()
            elif self.state == WSRequest_CONNECTED:
                self.handle_connected()

    def handle_uninit(self):
        try:
            headers = read_http_headers(self.data)
        except ValueError:
            return self.handle_bad_request()

        # ensure that http request is a GET request and HTTP/1.1
        if headers[rhh_method] != "GET" or headers[rhh_proto] != "HTTP/1.1":
            return self.handle_bad_request()

        if headers["Upgrade"].lower() != "websocket" or not (
            headers["Connection"] and "upgrade" in headers["Connection"].lower()
        ):
            return self.handle_bad_request()

        wsversion = headers["Sec-WebSocket-Version"]
        if wsversion != "13":
            return self.handle_bad_request()

        wskey = headers["Sec-WebSocket-Key"]
        wsaccept = base64.b64encode(
            hashlib.sha1(wskey.encode() + WS_MAGIC).digest()
        ).decode()
        response = f"""\
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: {wsaccept}

""".replace(
            "\n", "\r\n"
        ).encode()

        # create wsconn
        self.wsconn = WSConn(self.request)

        self.request.send(response)
        self.state = WSRequest_CONNECTED

        self.server.dispatch_connect(self.wsconn)

    def handle_connected(self):
        frame = None
        try:
            frame = WSFrame(self.data)
        except ValueError:
            print(self.data, "bad input")
            return

        if frame.opcode == 0x8:
            # close connection
            self.server.dispatch_close(self.wsconn)
            self.request.close()
            self.state = -1
            return

        if not frame.fin or frame.opcode == 0:
        
            raise ValueError

        while len(frame.data) < frame.payload_length:
            # this could be dos'd so easily idk know why i'm doing this
            frame.data.extend(self.request.recv(frame.payload_length - len(frame.data)))



        self.server.dispatch_receive(self.wsconn, frame.data)

    def handle_bad_request(self):
        if self.state == WSRequest_UNINIT:
            self.request.send(b"HTTP/1.1 400 Bad Request")

        self.request.close()
        self.state = -1

    def finish(self) -> None:
        # self.server.shutdown()
        pass
