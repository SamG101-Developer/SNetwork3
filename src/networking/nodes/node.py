from typing import Optional

from src.crypto_engines.digitial_signatures import digital_signatures
from src.crypto_engines.utils import byte_tools, key_pair, key_set
from src.crypto_engines.key_encapsulation import kem
from src.crypto_engines.secure_bytes import secure_bytes
from src.crypto_engines.symmetric import symmetric_cipher

from src.dht.dht import dht

from src.networking.connection_request  import response
from src.networking.connection_protocol import connection_protocol
from src.networking.ip import ip

import socket


class node:

    _my_static_asymmetric_key_pair: key_pair
    _my_ephemeral_asymmetric_key_pair: key_pair
    _socket: socket.socket

    _prev_node_ip: ip
    _next_node_ip: ip
    _candidate_next_node_ip: Optional[ip]

    _e2e_prev_node_master_key: key_set
    _e2e_next_node_master_key: key_set

    def __init__(self):
        ...

    def _handle_recv(self, response_: response, who_from: ip) -> None:
        match response_.command:
            case connection_protocol.COMMAND_CONNECT_REQUEST if self._qualified_to_accept_connection():
                self._handle_connection_request_command(response_, who_from)

            case connection_protocol.COMMAND_CONNECT_ACCEPT if self._candidate_next_node_ip and who_from == self._candidate_next_node_ip:
                self._handle_connection_accept_command(response_, who_from)

            case connection_protocol.COMMAND_CONNECT_REJECT if self._candidate_next_node_ip and who_from == self._candidate_next_node_ip:
                self._handle_connection_reject_command(response_, who_from)

            case connection_protocol.COMMAND_FORWARD if who_from == self._prev_node_ip:
                self._handle_forward_command(response_, who_from)

            case connection_protocol.COMMAND_BACKWARD if who_from == self._next_node_ip:
                self._handle_backward_command(response_, who_from)

    def _handle_connection_request_command(self, response_: response, who_from: ip) -> None:
        ...

    def _handle_connection_accept_command(self, response_: response, who_from: ip) -> None:
        their_static_public_key = dht.get_static_public_key(who_from)
        signed_wrapped_master_key, wrapped_master_key = byte_tools.unmerge(response_.data, 1)
        digital_signatures.verify(their_static_public_key, wrapped_master_key, signed_wrapped_master_key, self._my_ephemeral_public_key)
        self._e2e_next_node_master_key = key_set(kem.kem_unwrap(self._my_ephemeral_private_key, wrapped_master_key))

    def _handle_connection_reject_command(self, response_: response, who_from: ip) -> None:
        self._candidate_next_node_ip = None

    def _handle_forward_command(self, response_: response, who_from: ip) -> None:
        plain_text = symmetric_cipher.decrypt(self._e2e_prev_node_master_key.symmetric_cipher_key, response_.data)
        command, who_to, data = byte_tools.unmerge(plain_text, 2)
        self._socket.sendto(response(command, data=data).bytes, who_to)
                
    def _qualified_to_accept_connection(self) -> bool:
        return True

    @property
    def _my_ephemeral_public_key(self) -> secure_bytes:
        return self._my_ephemeral_asymmetric_key_pair.public_key

    @property
    def _my_ephemeral_private_key(self) -> secure_bytes:
        return self._my_ephemeral_asymmetric_key_pair.secret_key

    @property
    def _my_static_public_key(self) -> secure_bytes:
        return self._my_static_asymmetric_key_pair.public_key

    @property
    def _my_static_private_key(self) -> secure_bytes:
        return self._my_static_asymmetric_key_pair.secret_key
