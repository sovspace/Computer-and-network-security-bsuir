import logging
import datetime
import typing as tp

from bitarray import bitarray
from bitarray.util import ba2int

from des_cipher import DesCipher

from kerberos.models.data_types import TicketGrantingTicket, TicketGrantingService
from kerberos.models.responses import AuthenticationServiceResponse, TicketGrantingServerResponse
from kerberos.models.requests import AuthenticationServerRequest, TicketGrantingServerRequest

logger = logging.getLogger(__name__)


class AuthenticationServer:
    def __init__(self, cipher: DesCipher, tgs_id: int, as_tgs_key: bitarray, c_tgs_key: bitarray,
                 c_keys: tp.Dict[int, bitarray], valid_period_seconds: int) -> None:
        self._cipher = cipher
        self._tgs_id = tgs_id
        self._as_tgs_key = as_tgs_key
        self._c_tgs_key = c_tgs_key
        self._c_keys = c_keys
        self._valid_period_seconds = valid_period_seconds

    def send_response(self, request: AuthenticationServerRequest) -> tp.Optional[AuthenticationServiceResponse]:
        if request.client_id in self._c_keys:
            current_timestamp = int(datetime.datetime.utcnow().timestamp())
            ticket_granting_ticket = TicketGrantingTicket(request.client_id, self._tgs_id,
                                                          current_timestamp, self._valid_period_seconds)
            ticket_granting_ticket.encrypt_data(self._cipher, self._as_tgs_key)
            logger.info('Sending authentication server response')
            return AuthenticationServiceResponse(self._cipher, self._c_keys[request.client_id],
                                                 ticket_granting_ticket, self._c_tgs_key)
        else:
            logger.error('Wrong client id')
            return None


class TicketGrantingServer:
    def __init__(self, cipher: DesCipher, as_tgs_key: bitarray, c_tgs_key: bitarray,
                 tgs_ss_key: bitarray, c_ss_key: bitarray, valid_period_seconds: int) -> None:
        self._cipher = cipher
        self._as_tgs_key = as_tgs_key
        self._c_tgs_key = c_tgs_key

        self._tgs_ss_key = tgs_ss_key
        self._c_ss_key = c_ss_key
        self._valid_period_seconds = valid_period_seconds

    def send_response(self, request: TicketGrantingServerRequest) -> tp.Optional[TicketGrantingServerResponse]:
        ticket_granting_ticket = request.encrypted_ticket_granting_ticket
        ticket_granting_ticket.decrypt_data(self._cipher, self._as_tgs_key)

        authentication_block = request.encrypted_authentication_block
        authentication_block.decrypt_data(self._cipher, self._c_tgs_key)

        max_valid_timestamp = ba2int(ticket_granting_ticket.current_timestamp) + \
                              ba2int(ticket_granting_ticket.valid_period_seconds)
        if ticket_granting_ticket.client_id == authentication_block.client_id and \
                max_valid_timestamp > ba2int(authentication_block.current_timestamp):
            current_timestamp = int(datetime.datetime.utcnow().timestamp())
            ticket_granting_service = TicketGrantingService(ba2int(ticket_granting_ticket.client_id),
                                                            request.service_server_id,
                                                            current_timestamp, self._valid_period_seconds,
                                                            self._c_ss_key)
            ticket_granting_service.encrypt_data(self._cipher, self._tgs_ss_key)
            logger.info('Sending ticket granting server response')
            return TicketGrantingServerResponse(self._cipher, self._c_tgs_key, ticket_granting_service, self._c_ss_key)
        else:
            logger.error(
                'Different client id in ticket granting ticket and authentication block or authentication time expired')
            return None


class KerberosServer:
    def __init__(self, cipher: DesCipher, tgs_id: int, as_tgs_key: bitarray, c_tgs_key: bitarray,
                 c_keys: tp.Dict[int, bitarray], as_valid_period_seconds: int,
                 tgs_ss_key: bitarray, c_ss_key: bitarray, tgs_valid_period_seconds: int) -> None:
        self._authentication_server = AuthenticationServer(cipher, tgs_id, as_tgs_key, c_tgs_key,
                                                           c_keys, as_valid_period_seconds)
        self._ticket_granting_server = TicketGrantingServer(cipher, as_tgs_key, c_tgs_key, tgs_ss_key, c_ss_key,
                                                            tgs_valid_period_seconds)

    def send_response_ticket_granting_server(self, request: TicketGrantingServerRequest) -> \
            tp.Optional[TicketGrantingServerResponse]:
        return self._ticket_granting_server.send_response(request)

    def send_response_authentication_server(self, request: AuthenticationServerRequest) -> \
            tp.Optional[AuthenticationServiceResponse]:
        return self._authentication_server.send_response(request)
