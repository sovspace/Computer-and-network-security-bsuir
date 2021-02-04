import tempfile
import typing as tp

from vigenere_cipher import ViginereCipher
from caesar_cipher import CaesarCipher


def test_cipher(input_text_filename: str, cipher: tp.Union[CaesarCipher, ViginereCipher],
         key: tp.Union[int, bytes]) -> None:
    with open(input_text_filename, 'rb') as file:
        text = (b''.join(file.readlines())).decode('utf8')
        print(f'Исходный текст: {text}')

    encoded_text_bytes = cipher.encrypt_file(input_text_filename, key)
    encoded_text = encoded_text_bytes.decode('latin1')
    print(f'Зашифрованный текст: {encoded_text}')

    encoded_text_file = tempfile.TemporaryFile('r+b')
    encoded_text_file.write(encoded_text_bytes)
    encoded_text_file.seek(0)

    decoded_text_bytes = cipher.decrypt_file(encoded_text_file.name, key)
    decoded_text = decoded_text_bytes.decode('utf-8')
    print(f'Расщифрованый текст: {decoded_text}', end='\n\n')


def main() -> None:
    print('Тестовый случай: русский язык, шифр Цезаря, ключ 10')
    test_cipher('russian_text.txt', CaesarCipher(), 10)

    print('Тестовый случай: английский язык, шифр Цезаря, ключ 5')
    test_cipher('english_text.txt', CaesarCipher(), 5)

    print('Тестовый случай: русский язык, шифр Виженера, ключ \'суперсекретныйключ\'')
    test_cipher('russian_text.txt', ViginereCipher(), 'суперсекретныйключ'.encode('utf-8'))

    print('Тестовый случай: английский язык, шифр Цезаря, ключ \'supersecretkey\'')
    test_cipher('english_text.txt', ViginereCipher(), b'supersecretkey')


if __name__ == '__main__':
    main()
