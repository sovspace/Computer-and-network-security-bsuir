import itertools

from alphabet import Alphabet
from utils import get_letter_alphabet_position


class ViginereCipher:
    @staticmethod
    def _encrypt_letter(message_letter: str, key_letter: str, alphabet: Alphabet) -> str:
        message_letter_alphabet_position = get_letter_alphabet_position(message_letter, alphabet)
        key_letter_alphabet_position = get_letter_alphabet_position(key_letter, alphabet)
        if message_letter.isupper():
            return chr((message_letter_alphabet_position + key_letter_alphabet_position) % alphabet.size + ord(
                alphabet.upper_first_letter))
        else:
            return chr((message_letter_alphabet_position + key_letter_alphabet_position) % alphabet.size + ord(
                alphabet.lower_first_letter))

    @staticmethod
    def encrypt(message: str, key: str, alphabet: Alphabet) -> str:
        result_message_letters = []
        for message_letter, key_letter in zip(message, itertools.cycle(key)):
            encrypted_letter = ViginereCipher._encrypt_letter(message_letter, key_letter, alphabet)
            result_message_letters.append(encrypted_letter)
        return ''.join(result_message_letters)

    @staticmethod
    def _decrypt_letter(message_letter: str, key_letter: str, alphabet: Alphabet) -> str:
        message_letter_alphabet_position = get_letter_alphabet_position(message_letter, alphabet)
        key_letter_alphabet_position = get_letter_alphabet_position(key_letter, alphabet)
        if message_letter.isupper():
            return chr((message_letter_alphabet_position - key_letter_alphabet_position) % alphabet.size + ord(
                alphabet.upper_first_letter))
        else:
            return chr((message_letter_alphabet_position - key_letter_alphabet_position) % alphabet.size + ord(
                alphabet.lower_first_letter))

    @staticmethod
    def decrypt(message: str, key: str, alphabet: Alphabet) -> str:
        result_message_letters = []
        for message_letter, key_letter in zip(message, itertools.cycle(key)):
            encrypted_letter = ViginereCipher._decrypt_letter(message_letter, key_letter, alphabet)
            result_message_letters.append(encrypted_letter)
        return ''.join(result_message_letters)
