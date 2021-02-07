import logging
import typing as tp
import datetime

import bitarray

from kerberos.des_cipher import DesCipher
from kerberos.models.data_types import AuthenticationBlock
from kerberos.models.requests import AuthenticationServerRequest, TicketGrantingServerRequest, ServiceServerRequest
from kerberos.models.responses import AuthenticationServiceResponse, TicketGrantingServerResponse, ServiceServerResponse

logger = logging.getLogger(__name__)


class Client:
    def __init__(self, cipher: DesCipher, client_id: int, client_key: bitarray):
        self._cipher = cipher
        self._client_id = client_id
        self._client_key = client_key
        self._c_tgs_key: tp.Optional[bitarray] = None
        self._c_ss_key: tp.Optional[bitarray] = None

    def make_request_authentication_server(self) -> AuthenticationServerRequest:
        logger.info('Request authentication server')
        return AuthenticationServerRequest(self._client_id)

    def make_request_ticket_granting_server(self, response: AuthenticationServiceResponse,
                                            requested_service_server_id: int) -> TicketGrantingServerRequest:
        ticket_granting_ticket = response.encrypted_ticket_granting_ticket
        ticket_granting_ticket.decrypt_data(self._cipher, self._client_key)

        self._c_tgs_key = self._cipher.decrypt(response.encrypted_encryption_key, self._client_key)[8:]
        current_timestamp = int(datetime.datetime.utcnow().timestamp())
        authentication_block = AuthenticationBlock(self._client_id, current_timestamp)
        authentication_block.encrypt_data(self._cipher, self._c_tgs_key)
        logger.info('Request ticket granting server')
        return TicketGrantingServerRequest(ticket_granting_ticket, authentication_block, requested_service_server_id)

    def make_request_service_server(self, response: TicketGrantingServerResponse) -> ServiceServerRequest:
        assert self._c_tgs_key is not None
        ticket_granting_service = response.encrypted_ticket_granting_service
        ticket_granting_service.decrypt_data(self._cipher, self._c_tgs_key)
        self._c_ss_key = self._cipher.decrypt(response.encrypted_encryption_key, self._c_tgs_key)[8:]
        current_timestamp = int(datetime.datetime.utcnow().timestamp())
        authentication_block = AuthenticationBlock(self._client_id, current_timestamp)
        authentication_block.encrypt_data(self._cipher, self._c_ss_key)
        logger.info('Request service server')
        return ServiceServerRequest(ticket_granting_service, authentication_block)
