from src.crypto_engines.digitial_signatures import digital_signatures
from src.crypto_engines.utils import byte_tools, key_pair
from src.crypto_engines.secure_bytes import secure_bytes

from src.networking.connection_request  import response
from src.networking.connection_protocol import connection_protocol
from src.networking.ip import ip


class node:
    my_ephemeral_asymmetric_key_pair: key_pair

    def _handle_prev_node_connection_recv(self, prev_node_response: response, who_from: ip) -> None:
        match response.command:
            case connection_protocol.COMMAND_CONNECT_REQUEST:
                their_ephemeral_public_key, signature = byte_tools.unmerge(response.data, 1)
                their_static_public_key = dht.get_static_public_key(who_from)
                assert digital_signatures.verify(their_static_public_key, their_ephemeral_public_key, signature, self._my_ephemeral_public_key)

    @property
    def _my_ephemeral_public_key(self) -> secure_bytes:
        return self.my_ephemeral_asymmetric_key_pair.public_key

    @property
    def _my_ephemeral_private_key(self) -> secure_bytes:
        return self.my_ephemeral_asymmetric_key_pair.secret_key
