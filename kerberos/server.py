import logging
import typing as tp

import bitarray
from bitarray.util import ba2int

from des_cipher import DesCipher
from kerberos.models.requests import ServiceServerRequest
from kerberos.models.responses import ServiceServerResponse

logger = logging.getLogger(__name__)


class Server:
    def __init__(self, cipher: DesCipher, c_ss_key: bitarray, tgs_ss_key: bitarray) -> None:
        self.cipher = cipher
        self.c_ss_key = c_ss_key
        self.tgs_ss_key = tgs_ss_key

    def send_response(self, request: ServiceServerRequest) -> tp.Optional[ServiceServerResponse]:
        ticket_granting_service = request.encrypted_ticket_granting_service
        ticket_granting_service.decrypt_data(self.cipher, self.tgs_ss_key)

        authentication_block = request.encrypted_authentication_block
        authentication_block.decrypt_data(self.cipher, self.c_ss_key)

        max_valid_timestamp = ba2int(ticket_granting_service.current_timestamp) + \
                              ba2int(ticket_granting_service.valid_period_seconds)
        if max_valid_timestamp > ba2int(
                authentication_block.current_timestamp) and \
                authentication_block.client_id == ticket_granting_service.client_id:
            service_server_response = ServiceServerResponse(self.cipher, self.c_ss_key,
                                                            ba2int(authentication_block.current_timestamp) + 1)
            logger.info('Sending service server response')
            return service_server_response
        else:
            logger.error('Different client id in ticket granting ticket and authentication block')
            return None
