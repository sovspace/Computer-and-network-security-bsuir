import itertools


class ViginereCipher:
    CHARS_AMOUNT_IN_BYTE = 256

    @staticmethod
    def _encrypt_byte(message_byte: bytes, key_byte_ord: int) -> int:
        return (ord(message_byte) + key_byte_ord) % ViginereCipher.CHARS_AMOUNT_IN_BYTE

    @staticmethod
    def encrypt_file(filename: str, key: bytes) -> bytes:
        with open(filename, 'rb') as file:
            bytes_list = []
            cycle_key = itertools.cycle(key)
            while byte := file.read(1):
                encrypted_byte = ViginereCipher._encrypt_byte(byte, next(cycle_key))
                bytes_list.append(encrypted_byte)
        return bytes(bytes_list)

    @staticmethod
    def _decrypt_byte(message_byte: bytes, key_byte_ord: int) -> int:
        return (ord(message_byte) - key_byte_ord) % ViginereCipher.CHARS_AMOUNT_IN_BYTE

    @staticmethod
    def decrypt_file(filename: str, key: bytes) -> bytes:
        with open(filename, 'rb') as file:
            bytes_list = []
            cycle_key = itertools.cycle(key)
            while byte := file.read(1):
                decrypted_byte = ViginereCipher._decrypt_byte(byte, next(cycle_key))
                bytes_list.append(decrypted_byte)
        return bytes(bytes_list)
