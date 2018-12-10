# The `cpu_type_t` value for Mach-O header
# https://opensource.apple.com/source/cctools/cctools-836/include/mach/machine.h
CPU_TYPE_ARM = 0xc
CPU_TYPE_ARM64 = 0x100000c
CPU_TYPE_I386 = 0x1000007
CPU_TYPE_X86_64 = CPU_TYPE_I386


class MachBase:

    def __init__(self):
        pass

    @classmethod
    def parse_from_bytes(cls, _bytes):
        return cls()

    def get_size(self):
        return 0


class MachHeader(MachBase):

    MH_TOTAL_SIZE = 28

    MH_MAGIC_RANGE = (0, 4)
    MH_CPUTYPE_RANGE = (4, 4)
    MH_CPUSUBTYPE_RANGE = (8, 4)
    MH_FILETYPE_RANGE = (12, 4)
    MH_NCMDS_RANGE = (16, 4)
    MH_SIZEOFCMDS_RANGE = (20, 4)
    MH_FLAGS_RANGE = (24, 4)

    MH_MAGIC_32 = 0xfeedface
    MH_MAGIC_64 = 0xfeedfacf

    def __init__(self):
        self.magic = 0
        self.cputype = 0
        self.cpusubtype = 0
        self.filetype = 0
        self.ncmds = 0
        self.sizeofcmds = 0
        self.flags = 0

    @classmethod
    def parse_from_bytes(cls, _bytes):
        mh = cls()
        mh.magic = _parse_int(_bytes[0:4])
        mh.cputype = _parse_int(_bytes[4:8])
        mh.cpusubtype = _parse_int(_bytes[8:12])
        mh.filetype = _parse_int(_bytes[12:16])
        mh.ncmds = _parse_int(_bytes[16:20])
        mh.sizeofcmds = _parse_int(_bytes[20:24])
        mh.flags = _parse_int(_bytes[24:28])
        return mh

    def get_size(self):
        return MachHeader.MH_TOTAL_SIZE


class MachHeader64(MachHeader):

    MH_TOTAL_SIZE = 32
    MH_RESERVED_RANGE = (28, 4)

    def __init__(self):
        super().__init__()
        self.reserved = 0

    @classmethod
    def parse_from_bytes(cls, _bytes):
        mh_64 = super().parse_from_bytes(_bytes)
        mh_64.reserved = _parse_int(_bytes[28:32])
        return mh_64

    def get_size(self):
        return MachHeader64.MH_TOTAL_SIZE


class LoadCommand(MachBase):

    LC_TOTAL_SIZE = 8
    LC_CMD_RANGE = (0, 4)
    LC_CMD_CMDSIZE = (4, 8)

    LC_SEGMENT = 0x1
    LC_SEGMENT_64 = 0x19

    def __init__(self):
        self.cmd = 0
        self.cmdsize = 0

    @classmethod
    def parse_from_bytes(cls, _bytes):
        lc = cls()
        lc.cmd = _parse_int(_bytes[0:4])
        lc.cmdsize = _parse_int(_bytes[4:8])
        return lc

    def get_size(self):
        return LoadCommand.LC_TOTAL_SIZE


class SegmentCommand(LoadCommand):

    SC_TOTAL_SIZE = 56
    SC_SEGNAME_RANGE = (8, 16)
    SC_VMADDR_RANGE = (24, 4)
    SC_VMSIZE_RANGE = (28, 4)
    SC_FILEOFF_RANGE = (32, 4)
    SC_FILESIZE_RANGE = (36, 4)
    SC_MAXPROT_RANGE = (40, 4)
    SC_INITPROT_RANGE = (44, 4)
    SC_NSECTS_RANGE = (48, 4)
    SC_FLAGS_RANGE = (52, 4)

    def __init__(self):
        super().__init__()
        self.segname = ''
        self.vmaddr = 0x0
        self.vmsize = 0
        self.fileoff = 0
        self.filesize = 0
        self.maxprot = 0
        self.initprot = 0
        self.nsects = 0
        self.flags = 0

    @classmethod
    def parse_from_bytes(cls, _bytes):
        sc = cls()
        sc.cmd = _parse_int(_bytes[0:4])
        sc.cmdsize = _parse_int(_bytes[4:8])
        sc.segname = _parse_str(_bytes[8:24])
        sc.vmaddr = _parse_int(_bytes[24:28])
        sc.vmsize = _parse_int(_bytes[28:32])
        sc.fileoff = _parse_int(_bytes[32:36])
        sc.filesize = _parse_int(_bytes[36:40])
        sc.maxprot = _parse_int(_bytes[40:44])
        sc.initprot = _parse_int(_bytes[44:48])
        sc.nsects = _parse_int(_bytes[48:52])
        sc.flags = _parse_int(_bytes[52:56])
        return sc

    def get_size(self):
        return SegmentCommand.SC_TOTAL_SIZE


class SegmentCommand64(SegmentCommand):

    SC_TOTAL_SIZE = 72
    SC_VMADDR_RANGE = (24, 8)
    SC_VMSIZE_RANGE = (32, 8)
    SC_FILEOFF_RANGE = (40, 8)
    SC_FILESIZE_RANGE = (48, 8)
    SC_MAXPROT_RANGE = (56, 4)
    SC_INITPROT_RANGE = (60, 4)
    SC_NSECTS_RANGE = (64, 4)
    SC_FLAGS_RANGE = (68, 4)

    @classmethod
    def parse_from_bytes(cls, _bytes):
        sc64 = cls()
        sc64.cmd = _parse_int(_bytes[0:4])
        sc64.cmdsize = _parse_int(_bytes[4:8])
        sc64.segname = _parse_str(_bytes[8:24])
        sc64.vmaddr = _parse_int(_bytes[24:32])
        sc64.vmsize = _parse_int(_bytes[32:40])
        sc64.fileoff = _parse_int(_bytes[40:48])
        sc64.filesize = _parse_int(_bytes[48:56])
        sc64.maxprot = _parse_int(_bytes[56:60])
        sc64.initprot = _parse_int(_bytes[60:64])
        sc64.nsects = _parse_int(_bytes[64:68])
        sc64.flags = _parse_int(_bytes[68:72])
        return sc64

    def get_size(self):
        return SegmentCommand64.SC_TOTAL_SIZE


class Section(MachBase):

    S_TOTAL_SIZE = 68
    S_SECTNAME_RANGE = (0, 16)
    S_SEGNAME_RANGE = (16, 32)
    S_ADDR_RANGE = (32, 36)
    S_SIZE_RANGE = (36, 40)
    S_OFFSET_RANGE = (40, 44)
    S_ALIGN_RANGE = (44, 48)
    S_RELOFF_RANGE = (48, 52)
    S_NRELOC_RANGE = (52, 56)
    S_FLAGS_RANGE = (56, 60)
    S_RESERVED1_RANGE = (60, 64)
    S_RESERVED2_RANGE = (64, 68)

    def __init__(self):
        self.sectname = ''
        self.segname = ''
        self.addr = 0x0
        self.size = 0
        self.offset = 0
        self.align = 0
        self.reloff = 0
        self.nreloc = 0
        self.flags = 0
        self.reserved1 = 0
        self.reserved2 = 0

    @classmethod
    def parse_from_bytes(cls, _bytes):
        section = cls()
        section.sectname = _parse_str(_bytes[0:16])
        section.segname = _parse_str(_bytes[16:32])
        section.addr = _parse_int(_bytes[32:36])
        section.size = _parse_int(_bytes[36:40])
        section.offset = _parse_int(_bytes[40:44])
        section.align = _parse_int(_bytes[44:48])
        section.reloff = _parse_int(_bytes[48:52])
        section.nreloc = _parse_int(_bytes[52:56])
        section.flags = _parse_int(_bytes[56:60])
        section.reserved1 = _parse_int(_bytes[60:64])
        section.reserved2 = _parse_int(_bytes[64:68])
        return section

    def get_size(self):
        return Section.S_TOTAL_SIZE


class Section64(Section):

    S_TOTAL_SIZE = 80
    S_ADDR_RANGE = (32, 8)
    S_SIZE_RANGE = (40, 8)
    S_OFFSET_RANGE = (48, 4)
    S_ALIGN_RANGE = (52, 4)
    S_RELOFF_RANGE = (56, 4)
    S_NRELOC_RANGE = (60, 4)
    S_FLAGS_RANGE = (64, 4)
    S_RESERVED1_RANGE = (68, 4)
    S_RESERVED1_RANGE = (72, 4)
    S_RESERVED3_RANGE = (76, 4)

    def __init__(self):
        super().__init__()
        self.reserved3 = 0

    @classmethod
    def parse_from_bytes(cls, _bytes):
        section = cls()
        section.sectname = _parse_str(_bytes[0:16])
        section.segname = _parse_str(_bytes[16:32])
        section.addr = _parse_int(_bytes[32:40])
        section.size = _parse_int(_bytes[40:48])
        section.offset = _parse_int(_bytes[48:52])
        section.align = _parse_int(_bytes[52:56])
        section.reloff = _parse_int(_bytes[56:60])
        section.nreloc = _parse_int(_bytes[60:64])
        section.flags = _parse_int(_bytes[64:68])
        section.reserved1 = _parse_int(_bytes[68:72])
        section.reserved2 = _parse_int(_bytes[72:76])
        section.reserved3 = _parse_int(_bytes[76:80])
        return section

    def get_size(self):
        return Section.S_TOTAL_SIZE


# Inner Function
def _parse_int(_bytes):
    temp_bytes = b''
    for i in range(len(_bytes)):
        temp_bytes = _bytes[i: i + 1] + temp_bytes
    return int(temp_bytes.hex(), 16)


def _parse_str(_bytes):
    return _bytes.decode('utf-8')
