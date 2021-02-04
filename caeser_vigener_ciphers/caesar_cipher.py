

class CaesarCipher:
    CHARS_AMOUNT_IN_BYTE = 256

    @staticmethod
    def _encrypt_byte(byte: bytes, key: int) -> int:
        return (ord(byte) + key) % CaesarCipher.CHARS_AMOUNT_IN_BYTE

    @staticmethod
    def encrypt_file(filename: str, key: int) -> bytes:
        with open(filename, 'rb') as file:
            bytes_list = []
            while byte := file.read(1):
                encrypted_byte = CaesarCipher._encrypt_byte(byte, key)
                bytes_list.append(encrypted_byte)
        return bytes(bytes_list)

    @staticmethod
    def _decrypt_byte(byte: bytes, key: int) -> int:
        return (ord(byte) - key) % CaesarCipher.CHARS_AMOUNT_IN_BYTE

    @staticmethod
    def decrypt_file(filename: str, key: int) -> bytes:
        with open(filename, 'rb') as file:
            bytes_list = []
            while byte := file.read(1):
                decrypted_byte = CaesarCipher._decrypt_byte(byte, key)
                bytes_list.append(decrypted_byte)
        return bytes(bytes_list)
