from alphabet import Alphabet
from utils import get_letter_alphabet_position


class CaesarCipher:
    @staticmethod
    def _encrypt_letter(letter: str, key: int, alphabet: Alphabet) -> str:
        letter_alphabet_position = get_letter_alphabet_position(letter, alphabet)
        if letter.isupper():
            return chr((letter_alphabet_position + key) % alphabet.size + ord(alphabet.upper_first_letter))
        else:
            return chr((letter_alphabet_position + key) % alphabet.size + ord(alphabet.lower_first_letter))

    @staticmethod
    def encrypt(message: str, key: int, alphabet: Alphabet) -> str:
        result_message_letters = []
        for letter in message:
            encrypted_letter = CaesarCipher._encrypt_letter(letter, key, alphabet)
            result_message_letters.append(encrypted_letter)
        return ''.join(result_message_letters)

    @staticmethod
    def _decrypt_letter(letter: str, key: int, alphabet: Alphabet) -> str:
        letter_alphabet_position = get_letter_alphabet_position(letter, alphabet)
        if letter.isupper():
            return chr((letter_alphabet_position - key) % alphabet.size + ord(alphabet.upper_first_letter))
        else:
            return chr((letter_alphabet_position - key) % alphabet.size + ord(alphabet.lower_first_letter))

    @staticmethod
    def decrypt(message: str, key: int, alphabet: Alphabet) -> str:
        result_message_letters = []
        for letter in message:
            decrypted_letter = CaesarCipher._decrypt_letter(letter, key, alphabet)
            result_message_letters.append(decrypted_letter)
        return ''.join(result_message_letters)
