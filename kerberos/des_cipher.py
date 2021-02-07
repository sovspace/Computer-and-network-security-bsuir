import typing as tp
import numpy as np
import dataclasses

from bitarray import bitarray
from bitarray.util import ba2int, int2ba

from utils import left_cycle_shift


@dataclasses.dataclass
class DesCipherParameters:
    ip_permutation: tp.List[int]
    e_permutation: tp.List[int]
    s_boxes: tp.List[tp.List[tp.List[int]]]
    p_permutation: tp.List[int]
    pc_1_permutation: tp.List[int]
    pc_2_permutation: tp.List[int]


class DesCipher:
    def __init__(self, parameters: DesCipherParameters) -> None:
        self._ip_permutation = parameters.ip_permutation
        self._inverse_ip_permutation = self._inverse_permutation(parameters.ip_permutation)

        self._e_permutation = parameters.e_permutation
        self._s_boxes = parameters.s_boxes
        self._p_permutation = parameters.p_permutation

        self._pc_1_permutation = parameters.pc_1_permutation
        self._pc_2_permutation = parameters.pc_2_permutation

    @staticmethod
    def _inverse_permutation(permutation: tp.List[int]) -> tp.List[int]:
        inverse_permutation = [0] * len(permutation)
        for index, element in enumerate(permutation):
            inverse_permutation[element] = index
        return inverse_permutation

    @staticmethod
    def _make_permutation(block: bitarray, permutation: tp.List[int]) -> bitarray:
        result_block = bitarray(len(block))
        for to_position, from_position in enumerate(permutation):
            result_block[to_position] = block[from_position]
        return result_block

    @staticmethod
    def _make_extension(block: bitarray, extension_permutation: tp.List[int]) -> bitarray:
        result_block = bitarray(len(extension_permutation))

        for to_position, from_position in enumerate(extension_permutation):
            result_block[to_position] = block[from_position]
        return result_block

    @staticmethod
    def _make_s_box_conversion(block: bitarray, s_boxes: tp.List[tp.List[tp.List[int]]]) -> bitarray:
        result_bitarray = bitarray()
        for i in range(8):
            current_six_bits = block[i * 6: (i + 1) * 6]
            s_box_conversion_result = int2ba(s_boxes[i][ba2int(current_six_bits[:2])][ba2int(current_six_bits[2:])],
                                             length=4)
            result_bitarray += s_box_conversion_result
        return result_bitarray

    def _feistel_function(self, block_part: bitarray, key: bitarray) -> bitarray:
        extended_block = self._make_extension(block_part, self._e_permutation)
        block_key_xor = key ^ extended_block
        s_box_conversed_block = self._make_s_box_conversion(block_key_xor, self._s_boxes)
        return self._make_permutation(s_box_conversed_block, self._p_permutation)

    def _encryption_cycle(self, block_left_part: bitarray, block_right_part: bitarray,
                          key: bitarray) -> tp.Tuple[bitarray, bitarray]:
        new_block_right_part = block_left_part ^ self._feistel_function(block_right_part, key)
        return block_right_part, new_block_right_part

    def _decryption_cycle(self, block_left_part: bitarray, block_right_part: bitarray,
                          key: bitarray) -> tp.Tuple[bitarray, bitarray]:
        new_block_left_part = block_right_part ^ self._feistel_function(block_left_part, key)
        return new_block_left_part, block_left_part

    def _make_keys(self, left_key_part: bitarray, right_key_part: bitarray, round_no: int) -> \
            tp.Tuple[bitarray, bitarray, bitarray]:

        new_left_key_part: bitarray = left_cycle_shift(left_key_part, round_no % 2 + 1)
        new_right_key_part: bitarray = left_cycle_shift(right_key_part, round_no % 2 + 1)
        feistel_key = self._make_extension(new_left_key_part + new_right_key_part, self._pc_2_permutation)

        return new_left_key_part, new_right_key_part, feistel_key

    @staticmethod
    def generate_parameters() -> DesCipherParameters:
        ip_permutation = np.random.permutation(64).tolist()
        e_permutation = np.random.randint(0, 32, 48).tolist()
        s_boxes = []

        for _ in range(8):
            table = []
            for _ in range(4):
                table.append(np.random.permutation(16).tolist())
            s_boxes.append(table)

        p_permutation = np.random.permutation(32).tolist()
        pc_1_permutation = np.random.permutation(56).tolist()
        pc_2_permutation = np.random.permutation(56)[:48].tolist()
        return DesCipherParameters(ip_permutation, e_permutation, s_boxes, p_permutation, pc_1_permutation,
                                   pc_2_permutation)

    def _encrypt_block(self, block: bitarray, key: bitarray) -> bitarray:
        initial_block_permutation = self._make_permutation(block, self._ip_permutation)
        block_current_left_part = initial_block_permutation[:32]
        block_current_right_part = initial_block_permutation[32:]

        initial_key_permutation = self._make_permutation(key, self._pc_1_permutation)
        key_current_left_part = initial_key_permutation[:28]
        key_current_right_part = initial_key_permutation[28:]

        for round_no in range(16):
            key_current_left_part, key_current_right_part, feistel_key = self._make_keys(key_current_left_part,
                                                                                         key_current_right_part,
                                                                                         round_no)
            block_current_left_part, block_current_right_part = self._encryption_cycle(block_current_left_part,
                                                                                       block_current_right_part,
                                                                                       feistel_key)
        return self._make_permutation(block_current_left_part + block_current_right_part,
                                      self._inverse_ip_permutation)

    def encrypt(self, message: bitarray, key: bitarray) -> bitarray:
        encrypted_message = bitarray()
        extend_bits_amount = len(message) % 64

        if extend_bits_amount != 0:
            extended_message = bitarray([0] * (64 - extend_bits_amount)) + message
        else:
            extended_message = message

        for i in range(len(extended_message) // 64):
            encrypted_message += self._encrypt_block(extended_message[i * 64: (i + 1) * 64], key)
        return encrypted_message

    def _decrypt_block(self, block: bitarray, key: bitarray) -> bitarray:
        initial_key_permutation = self._make_permutation(key, self._pc_1_permutation)
        key_current_left_part = initial_key_permutation[:28]
        key_current_right_part = initial_key_permutation[28:]
        inverse_feistel_keys = []
        initial_block_permutation = self._make_permutation(block, self._ip_permutation)
        block_current_left_part = initial_block_permutation[:32]
        block_current_right_part = initial_block_permutation[32:]

        for round_no in range(16):
            key_current_left_part, key_current_right_part, feistel_key = self._make_keys(key_current_left_part,
                                                                                         key_current_right_part,
                                                                                         round_no)
            inverse_feistel_keys.append(feistel_key)

        for feistel_key in reversed(inverse_feistel_keys):
            block_current_left_part, block_current_right_part = self._decryption_cycle(block_current_left_part,
                                                                                       block_current_right_part,
                                                                                       feistel_key)
        return self._make_permutation(block_current_left_part + block_current_right_part,
                                      self._inverse_ip_permutation)

    def decrypt(self, message: bitarray, key: bitarray) -> bitarray:
        decrypted_message = bitarray()
        for i in range(len(message) // 64):
            decrypted_message += self._decrypt_block(message[i * 64: (i + 1) * 64], key)
        return decrypted_message

