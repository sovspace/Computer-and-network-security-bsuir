import sys
import socket


class Server:
    def __init__(self, server_host: str, server_port: str) -> None:
        self.server_host = server_host
        self.server_port = server_port

    def launch(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((self.server_host, int(self.server_port)))

        sock.listen()
        connection, address = sock.accept()
        while True:
            received_message = connection.recv(1024).decode('utf-8')
            print(received_message)


def main() -> None:
    if len(sys.argv) == 3:
        server = Server(*sys.argv[1:])
        server.launch()
    else:
        print('Wrong usage', file=sys.stderr)


if __name__ == '__main__':
    main()
