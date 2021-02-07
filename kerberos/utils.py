from bitarray import bitarray


def left_cycle_shift(array: bitarray, bits_amount: int) -> bitarray:
    return array[bits_amount:] + array[:bits_amount]
