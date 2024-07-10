import socket
import struct
import time

localIP = "0.0.0.0"

localPort = 10011

bufferSize = 1024

msgFromServer = "Hello UDP Client"
bytesToSend = str.encode(msgFromServer)


def raw_udp_mulitple_response():
    """
    UDP server that responds with two packets to each request
    """

    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)

    while True:
        b, addr = s.recvfrom(1024)
        sport, dport = struct.unpack_from("!HH", b, 20)

        if dport != 10011:
            continue

        response_packet_data = bytearray(
            struct.pack("!HHHH6s", dport, sport, 10, 0, bytes([0xFF] * 2))
        )

        print("sending 2 response packets")

        s.sendto(response_packet_data, addr)
        response_packet_data[-1] = 0
        time.sleep(0.2)
        s.sendto(response_packet_data, addr)

def raw_udp_reply_with_received_addr():
    """
    UDP server that responds with the given ip address
    """
    
    import ipaddress

    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)

    while True:
        b, addr = s.recvfrom(1024)
        sport, dport = struct.unpack_from("!HH", b, 20)

        if dport != 10011:
            continue

        response_packet_data = bytearray(
            struct.pack("!HHHHLH", dport, sport, 8 + 4, 0, int(ipaddress.IPv4Address(addr[0])), sport)
        )

        print("responding with packet")

        s.sendto(response_packet_data, addr)


if __name__ == "__main__":
    # raw_udp_mulitple_response()

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", localPort))
    data, addr = s.recvfrom(bufferSize)

    s.sendto(data, addr)
    
