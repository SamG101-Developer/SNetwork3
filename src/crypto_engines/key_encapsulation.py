from src.crypto_engines.utils import key_pair
from src.crypto_engines.secure_bytes import secure_bytes
from pqcrypto.kem import kyber1024


class kem:
    """
    The kem class contains a set of methods for wrapping/encapsulating and unwrapping/decapsulating shared keys, using
    a recipient's ephemeral public key for encapsulation, and the client's ephemeral private key for decryption.
    """

    @staticmethod
    def generate_keypair() -> key_pair:
        # create a new random keypair (used for generating ephemeral keys)
        return key_pair(kyber1024.generate_keypair())

    @staticmethod
    def kem_wrap(recipient_ephemeral_public_key: secure_bytes) -> tuple[secure_bytes, secure_bytes]:
        # wrap the plain key with the recipient's ephemeral public key
        cipher_text, plain_text = kyber1024.encrypt(recipient_ephemeral_public_key)
        return secure_bytes(cipher_text), secure_bytes(plain_text)

    @staticmethod
    def kem_unwrap(client_ephemeral_private_key: secure_bytes, encapsulated_key: secure_bytes) -> secure_bytes:
        # generate the random mask s and unwrap the received key with the
        return secure_bytes(kyber1024.decrypt(client_ephemeral_private_key, encapsulated_key))
