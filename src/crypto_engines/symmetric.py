from cryptography.hazmat.primitives.ciphers.aead import AESOCB3
from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap
from src.crypto_engines.utils import byte_tools
from src.crypto_engines.secure_bytes import secure_bytes
from os import urandom as csprng


class symmetric_cipher:
    """
    The symmetric_cipher class contains a set of methods for symmetric encryption using a shared key. The current mode
    is AES256 in OCB mode, which is authenticated. All e2e encryption is done with authenticated AES OCB, with a 256-bit
    key. IVs are random (not nonce + counter), as its easier to manage; counter object doesn't have to be passed in and
    incremented and saved somewhere; a random byte sequence is generated in the encryption method.
    """

    ALGORITHM = AESOCB3

    # length of keys and nonce
    KEY_LENGTH = 32
    NONCE_LENGTH = 16
    DEFAULT_ASSOCIATED_DATA = b""

    @staticmethod
    def generate_key() -> secure_bytes:
        # generate a random key
        random_key = csprng(symmetric_cipher.KEY_LENGTH)
        return secure_bytes(random_key)

    @staticmethod
    def wrap_new_key(current_key: secure_bytes, unwrapped_key: secure_bytes) -> secure_bytes:
        # wrap a new aes key with a current aes key
        wrapped_key = aes_key_wrap(current_key, unwrapped_key)
        return secure_bytes(wrapped_key)

    @staticmethod
    def unwrap_new_key(current_key: secure_bytes, wrapped_key: secure_bytes) -> secure_bytes:
        # unwrap a new aes key with a current aes key
        unwrapped_key = aes_key_unwrap(current_key, wrapped_key)
        return secure_bytes(unwrapped_key)

    @staticmethod
    def encrypt(data: secure_bytes, key: secure_bytes) -> secure_bytes:
        # encrypt the plaintext data with the key and a random iv - prepend the nonce to the ciphertext so that the
        # recipient can decrypt it (nonce doesn't have to be secret, but it does have to be unique)
        nonce = csprng(symmetric_cipher.NONCE_LENGTH)
        encryption_engine = symmetric_cipher.ALGORITHM(key)
        cipher_text = nonce + encryption_engine.encrypt(nonce, data, symmetric_cipher.DEFAULT_ASSOCIATED_DATA)
        return secure_bytes(cipher_text)

    @staticmethod
    def decrypt(data: secure_bytes, key: secure_bytes) -> secure_bytes:
        # extract the nonce, and decrypt the ciphertext data with the key and extracted iv. the tag check is done by the
        # decryption engine itself (it raises an exception if the tag is invalid)
        nonce, cipher_text = byte_tools.split_at_n(data, symmetric_cipher.NONCE_LENGTH)
        decryption_engine = symmetric_cipher.ALGORITHM(key)
        plain_text = decryption_engine.decrypt(nonce, cipher_text, symmetric_cipher.DEFAULT_ASSOCIATED_DATA)
        return secure_bytes(plain_text)
