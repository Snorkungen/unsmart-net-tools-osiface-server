import socket
from time import sleep

serverAddressPort = ("192.168.1.201", 10011)
bufferSize = 1024


if __name__ == "__main__":
    # with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    #     s.connect(serverAddressPort)
    #     data = s.recv(bufferSize)

    #     print ("received:", str(data))

    # Bind to the TCP port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

        s.bind(("127.48.0.1", 29902))
        s.getsockname()
        print("socket bound:", s.getsockname())
        s.listen()
        sleep(10000000)

