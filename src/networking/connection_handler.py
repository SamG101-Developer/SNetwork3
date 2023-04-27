from typing import Callable, Optional
from src.crypto_engines.utils import byte_tools
from src.crypto_engines.secure_bytes import secure_bytes
from src.crypto_engines.digitial_signatures import digital_signatures
from src.crypto_engines.symmetric import symmetric_cipher
from src.networking.connector import abstract_connector
from src.networking.connection_request import request, response
from src.networking.connection_protocol import connection_protocol
from src.networking.ip import ip


class connection_handler:
    @staticmethod
    def send_to_previous_node_init(plain_request: request, who_to: ip, my_static_private_key: secure_bytes, their_ephemeral_public_key: secure_bytes, connector: abstract_connector) -> None:
        signature, message = digital_signatures.sign(my_static_private_key, plain_request.bytes, their_ephemeral_public_key)
        signed_request = request(plain_request.command, plain_request.flag, byte_tools.merge(signature, message))
        connector.send(signed_request, who_to)

    @staticmethod
    def send_to_previous_node(plain_request: request, who_to: ip, symmetric_encryption_key: secure_bytes, connector: abstract_connector) -> None:
        cipher_text = symmetric_cipher.encrypt(plain_request.bytes, symmetric_encryption_key)
        encrypted_request = request(plain_request.command, plain_request.flag, cipher_text)
        connector.send(encrypted_request, who_to)

    @staticmethod
    def recv_from_previous_node_init(connector: abstract_connector, protocol_recv_handler: Callable) -> response:
        plain_response, who_from = connector.recv()
        protocol_recv_handler(plain_response, who_from)
        return plain_response

    @staticmethod
    def recv_from_previous_node(symmetric_decryption_key: secure_bytes, connector: abstract_connector, protocol_recv_handler: Callable) -> response:
        encrypted_response, who_from = connector.recv()
        protocol_recv_handler(symmetric_cipher.decrypt(encrypted_response.bytes, symmetric_decryption_key), who_from)
        return encrypted_response

    @staticmethod
    def send_to_next_node_init(plain_response: response, who_to: tuple[ip, ip, ip], symmetric_encryption_keys: tuple[secure_bytes, secure_bytes, secure_bytes]

