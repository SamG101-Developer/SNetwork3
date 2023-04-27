from src.crypto_engines.secure_bytes import secure_bytes
import argon2


class kdf:
    @staticmethod
    def derive_key(master_key: secure_bytes, customization_bytes: secure_bytes, tag_length: int) -> secure_bytes:
        return secure_bytes(argon2.PasswordHasher(hash_len=tag_length).hash(master_key + customization_bytes))
