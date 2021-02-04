import re
import typing as tp

from alphabet import Alphabet
from caesar_cipher import CaesarCipher
from vigenere_cipher import ViginereCipher

english_alphabet = Alphabet('a', 'A', 26)
russian_alphabet = Alphabet('а', 'А', 33)

english_text = '''LO, praise of the prowess of people-kings
of spear-armed Danes, in days long sped,
we have heard, and what honor the athelings won!
Oft Scyld the Scefing from squadroned foes,
from many a tribe, the mead-bench tore,
awing the earls. Since erst he lay
friendless, a foundling, fate repaid him:
for he waxed under welkin, in wealth he throve,
till before him the folk, both far and near,
who house by the whale-path, heard his mandate,
gave him gifts: a good king he!
'''

russian_text = '''Первая мысль вот она - бытие
вторая - отрицательная
это её отрицание, а теперь отрицание этого небытия
но мы всё таки изучаем эту книгу
целое, с этим же содержанием
и вернуться к этой же книге
теперь имея ввиду что содержание в ней есть
это что такое будет? - отрицание отрицания
движение изчезновения бытия в ничто, а ничто в бытие
ничто перешло в бытие, а это уже такое бытие
которое 2 этапа предполагает логических
2 логических шага
а это бытие, уже ничего не надо доказывать
бытие то мы уже знаем что оно переходит в ничто
то есть иное, чо не написано
иное же написано'''


def test_cipher(text: str, alphabet: Alphabet, cipher: tp.Union[CaesarCipher, ViginereCipher], key: tp.Union[str, int]) -> None:
    words_only_text = ''.join(re.findall(r'\w+', text))

    print(f'Исходный текст: {words_only_text}')
    encrypted_text = cipher.encrypt(words_only_text, key, alphabet)
    print(f'Зашифрованный текст: {encrypted_text}')
    decrypted_text = cipher.decrypt(encrypted_text, key, alphabet)
    print(f'Расшифрованный текст: {decrypted_text}', end='\n\n')


def main() -> None:
    print('Тестовый случай: русский язык, шифр Цезаря, ключ 10')
    test_cipher(russian_text, russian_alphabet, CaesarCipher(), 10)

    print('')
    print('Тестовый случай: английский язык, шифр Цезаря, ключ 5')
    test_cipher(english_text, english_alphabet, CaesarCipher(), 5)

    print('')
    print('Тестовый случай: русский язык, шифр Виженера, ключ \'суперсекретныйключ\'')
    test_cipher(russian_text, russian_alphabet, ViginereCipher(), 'суперсекретныйключ')

    print('Тестовый случай: английский язык, шифр Цезаря, ключ \'supersecretkey\'')
    test_cipher(english_text, english_alphabet, ViginereCipher(), 'supersecretkey')


if __name__ == '__main__':
    main()
