from utils import *

FAT_MAGIC = 0xcafebabe
FAT_CIGAM = 0xbebafeca


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


class FatArch(FatBase):

    FA_TOTAL_SIZE = 20
    FA_CPUTYPE_RANGE = (0, 4)
    FA_CPUSUBTYPE_RANGE = (4, 4)
    FA_OFFSET_RANGE = (8, 4)
    FA_SIZE_RANGE = (12, 4)
    FA_ALIGN_RANGE = (16, 4)

    def __init__(self):
        self.cputype = 0
        self.cpusubtype = 0
        self.offset = 0
        self.size = 0
        self.align = 0

    @classmethod
    def parse_from_bytes(cls, _bytes):
        fa = cls()
        fa.cputype = parse_int(_bytes[0:4])
        fa.cpusubtype = parse_int(_bytes[4:8])
        fa.offset = parse_int(_bytes[8:12])
        fa.size = parse_int(_bytes[12:16])
        fa.size = parse_int(_bytes[16:20])
        return fa

    def get_size(self):
        return FatArch.FA_TOTAL_SIZE
