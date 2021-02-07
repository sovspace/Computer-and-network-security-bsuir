from bitarray import bitarray
from bitarray.util import int2ba

from kerberos.des_cipher import DesCipher
from kerberos.models.data_types import TicketGrantingTicket, TicketGrantingService


class AuthenticationServiceResponse:
    def __init__(self, cipher: DesCipher, key: bitarray,
                 ticket_granting_ticket: TicketGrantingTicket, encryption_key: bitarray) -> None:
        self.encrypted_ticket_granting_ticket = ticket_granting_ticket
        self.encrypted_ticket_granting_ticket.encrypt_data(cipher, key)

        self.encrypted_encryption_key = cipher.encrypt(encryption_key, key)


class TicketGrantingServerResponse:
    def __init__(self, cipher: DesCipher, key: bitarray, ticket_granting_service: TicketGrantingService,
                 encryption_key: bitarray) -> None:
        self.encrypted_ticket_granting_service = ticket_granting_service
        self.encrypted_ticket_granting_service.encrypt_data(cipher, key)
        self.encrypted_encryption_key = cipher.encrypt(encryption_key, key)


class ServiceServerResponse:
    def __init__(self, cipher: DesCipher, key: bitarray, timestamp: int) -> None:
        self.encrypted_timestamp = cipher.encrypt(int2ba(timestamp), key)
