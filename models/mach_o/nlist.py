from utils import *

class Nlist():

    N_TOTAL_SIZE = 12
    N_N_STRX_RANGE = (0, 4)
    N_N_TYPE_RANGE = (4, 1)
    N_N_SECT_RANGE = (5, 1)
    N_N_DEST_RANGE = (6, 2)
    N_N_VALUE_RANGE = (8, 4)

    def __init__(self):
        self.n_strx = 0
        self.n_type = 0
        self.n_sect = 0
        self.n_desc = 0
        self.n_value = 0

    @classmethod
    def parse_from_bytes(cls, _bytes):
        nl = cls()
        nl.n_strx = parse_int(_bytes[0:4])
        nl.n_type = parse_int(_bytes[4:5])
        nl.n_sect = parse_int(_bytes[5:6])
        nl.n_desc = parse_int(_bytes[6:8])
        nl.n_value = parse_int(_bytes[8:12])
        return nl

    def get_size(self):
        return Nlist.N_TOTAL_SIZE


class Nlist64(Nlist):

    N_TOTAL_SIZE = 16
    N_N_VALUE_RANGE = (8, 8)

    def __init__(self):
        super().__init__()

    @classmethod
    def parse_from_bytes(cls, _bytes):
        nl = cls()
        nl.n_strx = parse_int(_bytes[0:4])
        nl.n_type = parse_int(_bytes[4:5])
        nl.n_sect = parse_int(_bytes[5:6])
        nl.n_desc = parse_int(_bytes[6:8])
        nl.n_value = parse_int(_bytes[8:16])
        return nl

    def get_size(self):
        return Nlist64.N_TOTAL_SIZE
