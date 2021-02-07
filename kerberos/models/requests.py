import dataclasses

from data_types import TicketGrantingTicket, AuthenticationBlock, TicketGrantingService


@dataclasses.dataclass
class AuthenticationServerRequest:
    client_id: int


@dataclasses.dataclass
class TicketGrantingServerRequest:
    encrypted_ticket_granting_ticket: TicketGrantingTicket
    encrypted_authentication_block: AuthenticationBlock
    service_server_id: int


@dataclasses.dataclass
class ServiceServerRequest:
    encrypted_ticket_granting_service: TicketGrantingService
    encrypted_authentication_block: AuthenticationBlock
