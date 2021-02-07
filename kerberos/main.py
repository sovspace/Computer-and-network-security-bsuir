import logging.config

from bitarray import bitarray

from kerberos.des_cipher import DesCipher
from kerberos.client import Client
from kerberos.kerberos_server import KerberosServer
from kerberos.server import Server

logging.config.fileConfig('logger_config.ini', disable_existing_loggers=False)


def launch(cipher: DesCipher, client_id: int, client_key: bitarray, requested_service_server_id: int,
           tgs_id: int, as_tgs_key: bitarray, c_tgs_key: bitarray, as_valid_period_seconds: int,
           tgs_ss_key: bitarray, c_ss_key: bitarray, tgs_valid_period_seconds: int) -> None:
    client = Client(cipher, client_id, client_key)
    kb_server = KerberosServer(cipher, tgs_id, as_tgs_key, c_tgs_key, {client_id: client_key},
                               as_valid_period_seconds, tgs_ss_key, c_ss_key, tgs_valid_period_seconds)
    service_server = Server(cipher, c_ss_key, tgs_ss_key)
    authentication_server_request = client.make_request_authentication_server()
    authentication_server_response = kb_server.send_response_authentication_server(authentication_server_request)
    if authentication_server_response is None:
        return None
    ticket_granting_server_request = client.make_request_ticket_granting_server(authentication_server_response,
                                                                                requested_service_server_id)
    ticket_granting_server_response = kb_server.send_response_ticket_granting_server(ticket_granting_server_request)
    if ticket_granting_server_response is None:
        return None

    service_server_request = client.make_request_service_server(ticket_granting_server_response)
    service_server.send_response(service_server_request)


launch(DesCipher(DesCipher.generate_parameters()), 42, bitarray(56), 101, 56, bitarray(56), bitarray(56),
       15, bitarray(56), bitarray(56), 15)
