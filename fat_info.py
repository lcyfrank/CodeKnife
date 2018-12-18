from utils import *

class FatBase:

    def __init__(self):
        pass

    @classmethod
    def parse_from_bytes(cls, _bytes):
        return cls()

    def get_size(self):
        return 0

    
class FatHeader(FatBase):

    FH_TOTAL_SIZE = 8
    FH_MAGIC_RANGE = (0, 4)
    FH_NFAT_ARCH_RANGE = (4, 4)

    def __init__(self):
        self.magic = 0x0
        self.nfat_arch = 0

    @classmethod
    def parse_from_bytes(cls, _bytes):
        fh = cls()
        fh.magic = parse_int(_bytes[0:4])
        fh.nfat_arch = parse_int(_bytes[4:8])
        return fh

    def get_size(self):
        return FatHeader.FH_TOTAL_SIZE
