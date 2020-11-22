from __future__ import division
import math


class CipherTransposition:
    def encrypt(self, data, key):
        message_size = len(data)

        if(key > message_size // 2):
            raise ValueError('Key is limited to half the length of message')
        else:
            encrypted_message = [''] * key
            for col in range(key):
                pointer = col
                while pointer < message_size:
                    encrypted_message[col] += data[pointer]
                    pointer += key

            encrypted_message = ''.join(encrypted_message)
            return encrypted_message


    def decrypt(self, data, key):
        num_of_columns = int(math.ceil(len(data) / key))
        num_of_rows = key
        num_of_shaded_boxes = (num_of_columns * num_of_rows) - len(data)

        data = [''] * num_of_columns

        col = 0
        row = 0

        for symbol in data:
            data[col] += symbol
            col += 1

            if (col == num_of_columns or
                 col == num_of_columns - 1 and
                 row >= num_of_rows - num_of_shaded_boxes):
                col = 0
                row += 1

        return ''.join(data)
