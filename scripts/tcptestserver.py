
import socket
localIP = "0.0.0.0"

localPort = 10011

bufferSize = 1024

if __name__ == "__main__":
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", localPort))
    s.listen()


    while True:
        tcp_sock, addr = s.accept()
        print("sending hello to:", addr)
        tcp_sock.send(b"Hello world")
        tcp_sock.close()
