from alphabet import Alphabet


def get_letter_alphabet_position(letter: str, alphabet: Alphabet) -> int:
    if letter.isupper():
        return ord(letter) - ord(alphabet.upper_first_letter)
    else:
        return ord(letter) - ord(alphabet.lower_first_letter)
