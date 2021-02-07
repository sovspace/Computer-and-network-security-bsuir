import dataclasses

from bitarray import bitarray
from bitarray.util import int2ba

from kerberos.des_cipher import DesCipher


@dataclasses.dataclass(init=False)
class TicketGrantingTicket:
    client_id: bitarray
    ticket_granting_server_id: bitarray
    current_timestamp: bitarray
    valid_period_seconds: bitarray

    def __init__(self, client_id: int, ticket_granting_server_id: int,
                 current_timestamp: int, valid_period_seconds: int) -> None:
        self.client_id = int2ba(client_id)
        self.ticket_granting_server_id = int2ba(ticket_granting_server_id)
        self.current_timestamp = int2ba(current_timestamp)
        self.valid_period_seconds = int2ba(valid_period_seconds)

    def encrypt_data(self, cipher: DesCipher, key: bitarray) -> None:
        field: dataclasses.Field
        for field in dataclasses.fields(self):
            setattr(self, field.name, cipher.encrypt(getattr(self, field.name), key))

    def decrypt_data(self, cipher: DesCipher, key: bitarray) -> None:
        field: dataclasses.Field
        for field in dataclasses.fields(self):
            setattr(self, field.name, cipher.decrypt(getattr(self, field.name), key))


@dataclasses.dataclass(init=False)
class AuthenticationBlock:
    client_id: bitarray
    current_timestamp: bitarray

    def __init__(self, client_id: int, current_timestamp: int) -> None:
        self.client_id = int2ba(client_id)
        self.current_timestamp = int2ba(current_timestamp)

    def encrypt_data(self, cipher: DesCipher, key: bitarray) -> None:
        field: dataclasses.Field
        for field in dataclasses.fields(self):
            setattr(self, field.name, cipher.encrypt(getattr(self, field.name), key))

    def decrypt_data(self, cipher: DesCipher, key: bitarray) -> None:
        field: dataclasses.Field
        for field in dataclasses.fields(self):
            setattr(self, field.name, cipher.decrypt(getattr(self, field.name), key))


@dataclasses.dataclass(init=False)
class TicketGrantingService:
    client_id: bitarray
    service_server_id: bitarray
    current_timestamp: bitarray
    valid_period_seconds: bitarray
    encryption_key: bitarray

    def __init__(self, client_id: int, service_server_id: int, current_timestamp: int,
                 valid_period_seconds: int, encryption_key: bitarray) -> None:
        self.client_id = int2ba(client_id)
        self.service_server_id = int2ba(service_server_id)
        self.current_timestamp = int2ba(current_timestamp)
        self.valid_period_seconds = int2ba(valid_period_seconds)
        self.encryption_key = encryption_key

    def encrypt_data(self, cipher: DesCipher, key: bitarray) -> None:
        field: dataclasses.Field
        for field in dataclasses.fields(self):
            setattr(self, field.name, cipher.encrypt(getattr(self, field.name), key))

    def decrypt_data(self, cipher: DesCipher, key: bitarray) -> None:
        field: dataclasses.Field
        for field in dataclasses.fields(self):
            setattr(self, field.name, cipher.decrypt(getattr(self, field.name), key))
