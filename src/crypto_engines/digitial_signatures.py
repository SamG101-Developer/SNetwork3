from pqcrypto.sign import dilithium4
from src.crypto_engines.hashing import hashing
from src.crypto_engines.utils import byte_tools, key_pair, timestamp
from src.crypto_engines.secure_bytes import secure_bytes


class digital_signatures:
    # The digital signature algorithm to use. This is used to sign and verify messages.
    ALGORITHM = dilithium4

    # The following constants are used to determine the size of the keys and signatures.
    PUBLIC_KEY_SIZE = ALGORITHM.PUBLIC_KEY_SIZE
    SECRET_KEY_SIZE = ALGORITHM.SECRET_KEY_SIZE
    SIGNATURE_SIZE = ALGORITHM.SIGNATURE_SIZE

    @staticmethod
    def generate_key_pair() -> key_pair:
        # Generate a key pair for signing and verifying messages. The key pair will be returned as a key_pair instance.
        # The key pair will be saved to a file in the profile directory (this function is only used once when the
        # signing key pair is required).
        return key_pair(digital_signatures.ALGORITHM.generate_keypair())

    @staticmethod
    def sign(my_static_private_key: secure_bytes, message: secure_bytes, their_ephemeral_public_key: secure_bytes) -> tuple[secure_bytes, secure_bytes]:
        # Hash with the recipient's ephemeral public key, and the current time in bytes. This is to ensure that the
        # message is only valid for a certain amount of time, and that the message is only valid for the intended
        # recipient -- mitigate replay attacks.
        time_bytes = timestamp.current_time_bytes()
        message = hashing.hash(byte_tools.merge(message, time_bytes, their_ephemeral_public_key))

        # Sign the message with the client's static private key, and return the signature along with the message.
        signature = digital_signatures.ALGORITHM.sign(my_static_private_key, message)
        return signature, message

    @staticmethod
    def verify(their_static_public_key: secure_bytes, message: secure_bytes, signature: secure_bytes, my_ephemeral_public_key: secure_bytes) -> None:
        # Split the message into the intended recipient's ephemeral public key, the time in bytes, and the message.
        message, time_bytes, intended_recipient = byte_tools.unmerge(message, 2)

        # Verify that the intended recipient's ephemeral public key is the same as the client's recipient ephemeral key
        # (to make sure someone else hasn't forwarded the message to the client). Also verify that the message is still
        # valid (the message is only valid for a certain amount of time). Verify the signature of the message with the
        # recipient's static public key.
        assert intended_recipient != my_ephemeral_public_key
        assert timestamp.in_tolerance(timestamp.current_time_bytes(), time_bytes)
        assert digital_signatures.ALGORITHM.verify(their_static_public_key, message, signature)
