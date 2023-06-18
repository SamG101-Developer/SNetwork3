from typing import Optional

from src.crypto_engines.digitial_signatures import digital_signatures
from src.crypto_engines.utils import byte_tools, key_pair, key_set
from src.crypto_engines.key_encapsulation import kem
from src.crypto_engines.secure_bytes import secure_bytes
from src.crypto_engines.symmetric import symmetric_cipher

from src.dht.dht import dht

from src.networking.connection_request  import request, response
from src.networking.connection_protocol import connection_protocol
from src.networking.ip import ip

import socket


class node:
    _my_static_asymmetric_key_pair: key_pair
    _my_ephemeral_asymmetric_key_pair: key_pair
    _socket: socket.socket

    _prev_node_ip: Optional[ip]
    _next_node_ip: Optional[ip]
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

            case connection_protocol.COMMAND_FORWARD if who_from == self._next_node_ip:
                self._handle_forward_command_to_next(response_, who_from)

            case connection_protocol.COMMAND_FORWARD if who_from == self._prev_node_ip:
                self._handle_forward_command_to_prev(response_, who_from)

            case connection_protocol.COMMAND_EXTEND_CIRCUIT if who_from == self._prev_node_ip:
                self._handle_extend_circuit_command(response_, who_from)


    def _handle_connection_request_command(self, response_: response, who_from: ip) -> None:
        ...

    # TODO -> Error handling
    #   - Invalid signature => increase potential attack vector, re-initialise circuit
    #   - Cannot find the node in the DHT => CRITICAL
    def _handle_connection_accept_command(self, response_: response, who_from: ip) -> None:
        # The client node receives a connection accept command from another node. The first operation performed is to
        # verify the signature of the KEMed symmetric master key. If the signature is valid, the client node will
        # KEM unwrap the symmetric master key and save it against the "next" node, so that any data sent and received
        # between this node and the next node in the route can be encrypted and decrypted.
        signed_wrapped_master_key_and_metadata, wrapped_master_key_and_metadata = byte_tools.unmerge(response_.data, 1)
        digital_signatures.verify(
            their_static_public_key=dht.get_static_public_key(who_from),
            message=wrapped_master_key_and_metadata,
            signature=signed_wrapped_master_key_and_metadata,
            my_ephemeral_public_key=self._my_ephemeral_public_key)

        # Save the key against the next node, and then initialise the packet handler. This will begin packet
        # interception, manipulation and injection, after exchanging the packet keys to the other nodes in the route
        # via the route itself.
        wrapped_master_key = byte_tools.unmerge(wrapped_master_key_and_metadata, 1)[0]
        unwrapped_master_key = kem.kem_unwrap(self._my_ephemeral_private_key, wrapped_master_key)
        self._e2e_next_node_master_key = key_set(unwrapped_master_key)

        # Additional operations are performed by client and circuit nodes in the inherited classes.


    # TODO -> Error handling
    #   - Invalid reason to reject => try reconnect once to the same node (different port)
    #   - Invalid signature 1 => try reconnect once to the same node (different port)
    #   - Invalid signature n => increase potential attack vector, re-initialise circuit
    #   - Cannot find the node in the DHT => CRITICAL
    def _handle_connection_reject_command(self, response_: response, who_from: ip) -> None:
        # The client node receives a connection reject command from another node. Check the signature of the reason
        # for rejection, and if there is a signature mismatch, then there is a possibility that someone had forced the
        # rejection, so retry the connection, to try to reduce the bias of node choices (prevent attacks where nodes
        # are forced to be used from exhaustion). If the signature is valid, then the client node will re-initialise
        # the circuit, and try to connect to another node.
        signed_reason_to_reject, reason_to_reject = response_.data
        digital_signatures.verify(
            their_static_public_key=dht.get_static_public_key(who_from),
            message=reason_to_reject,
            signature=signed_reason_to_reject,
            my_ephemeral_public_key=self._my_ephemeral_public_key)

        # Additional operations are performed by client and circuit nodes in the inherited classes.

    def _handle_forward_command_to_next(self, response_: response, who_from: ip) -> None:
        ...

    def _handle_forward_command_to_prev(self, response_: response, who_from: ip) -> None:
        ...

    def _handle_extend_circuit_command(self, request_: request, who_from: ip) -> None:
        # Clear all IP addresses (these could be non-Null from a previous circuit connection attempt). Generate a new
        # ephemeral asymmetric key pair, to ensure perfect forward secrecy, ensuring that each session is uniquely
        # encrypted.
        self._prev_node_ip = None
        self._next_node_ip = None
        self._my_ephemeral_asymmetric_key_pair = kem.generate_keypair()

        # The IP address of the next node will have been selected from the DHT by the client, and is therefore in the
        # payload of the request received from the previous node.
        who_to = ip.from_bytes(request.data)
        their_static_public_key = dht.get_static_public_key(who_to)
        signed_my_ephemeral_public_key, _ = digital_signatures.sign(
            my_static_private_key=self._my_static_private_key,
            message=self._my_ephemeral_public_key,
            their_id=their_static_public_key)

        # Set the candidate next node IP address, and send the connection request to the selected node. The
        # candidate IP address is required so that an incoming CON_ACC or CON_REJ command can be verified as being
        # as coming from the correct node.
        bytes_to_send = byte_tools.merge(signed_my_ephemeral_public_key, self._my_ephemeral_public_key)
        request_ = request(
            command=connection_protocol.COMMAND_CONNECT_REQUEST,
            flag=connection_protocol.FLAG_NONE,
            data=bytes_to_send)
        self._candidate_next_node_ip = who_to
        self._socket.sendto(request_.bytes, who_to.socket_format)

    def _qualified_to_accept_connection(self) -> bool:
        return True

    # TODO -> Wrong
    #   - incremental encryption required, not next key (needs to be symmetric)
    #   - split to forwarding forward and backward (encrypt n times or once)
    def _construct_forwarded_message(self, response_: response | request) -> secure_bytes:
        # Extract the data and command from the current response, and merge them into a request object,
        # and then extract the raw data out of that - simple way to ensure messages are uniform.
        data = byte_tools.merge(response.command, response_.data)
        command = connection_protocol.COMMAND_FORWARD
        plain_text = request(command, connection_protocol.FLAG_NONE, data).bytes

        # Encrypt the request with the authenticated symmetric key for the connection encryption between this node and
        # the previous node in the route.
        cipher_text = symmetric_cipher.encrypt(plain_text, self._e2e_prev_node_master_key.symmetric_cipher_key)
        return cipher_text

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
