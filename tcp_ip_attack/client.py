import logging
import sys
import socket

logger = logging.getLogger(__name__)


class Client:
    stop_message = 'EXIT'

    def __init__(self, server_host: str, server_port: str) -> None:
        self.server_host = server_host
        self.server_port = server_port

    def launch(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.server_host, int(self.server_port)))
        username = input('Print your username: ')
        while True:
            message_to_send = input(f'{username}: ')
            if message_to_send == self.stop_message:
                break
            else:
                if message_to_send:
                    sock.sendto(f'{username}: {message_to_send}'.encode('utf-8'),
                                (self.server_host, int(self.server_port)))
        sock.close()


def main():
    if len(sys.argv) == 3:
        user_chat = Client(*sys.argv[1:])
        user_chat.launch()
    else:
        print('Wrong usage', file=sys.stderr)


if __name__ == '__main__':
    main()
