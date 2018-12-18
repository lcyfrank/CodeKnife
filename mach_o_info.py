from utils import *
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

    def describe(self):
        print(self.__dict__)        


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
        mh.magic = parse_int(_bytes[0:4])
        mh.cputype = parse_int(_bytes[4:8])
        mh.cpusubtype = parse_int(_bytes[8:12])
        mh.filetype = parse_int(_bytes[12:16])
        mh.ncmds = parse_int(_bytes[16:20])
        mh.sizeofcmds = parse_int(_bytes[20:24])
        mh.flags = parse_int(_bytes[24:28])
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
        mh_64.reserved = parse_int(_bytes[28:32])
        return mh_64

    def get_size(self):
        return MachHeader64.MH_TOTAL_SIZE


class LoadCommand(MachBase):

    LC_TOTAL_SIZE = 8
    LC_CMD_RANGE = (0, 4)
    LC_CMD_CMDSIZE = (4, 8)

    LC_SEGMENT = 0x1
    LC_SEGMENT_64 = 0x19
    LC_SYMTAB = 0x2
    LC_DYSYMTAB = 0xb

    def __init__(self):
        self.cmd = 0
        self.cmdsize = 0

    @classmethod
    def parse_from_bytes(cls, _bytes):
        lc = cls()
        lc.cmd = parse_int(_bytes[0:4])
        lc.cmdsize = parse_int(_bytes[4:8])
        return lc

    def get_size(self):
        return LoadCommand.LC_TOTAL_SIZE


class SymtabCommand(LoadCommand):

    SC_TOTAL_SIZE = 24
    SC_SYMOFF_RANGE = (8, 4)
    SC_NSYMS_RANGE = (12, 4)
    SC_STROFF_RANGE = (16, 4)
    SC_STRSIZE_RANGE = (20, 4)

    def __init__(self):
        super().__init__()
        self.symoff = 0
        self.nsyms = 0
        self.stroff = 0
        self.strsize = 0

    @classmethod
    def parse_from_bytes(cls, _bytes):
        sc = cls()
        sc.cmd = parse_int(_bytes[0:4])
        sc.cmdsize = parse_int(_bytes[4:8])
        sc.symoff = parse_int(_bytes[8:12])
        sc.nsyms = parse_int(_bytes[12:16])
        sc.stroff = parse_int(_bytes[16:20])
        sc.strsize = parse_int(_bytes[20:24])
        return sc

    def get_size(self):
        return SymtabCommand.SC_TOTAL_SIZE


class DysymtabCommand(LoadCommand):

    DC_TOTAL_SIZE = 80
    DC_ILOCALSYM_RANGE = (8, 4)
    DC_NLOCALSYM_RANGE = (12, 4)
    DC_IEXTDEFSYM_RANGE = (16, 4)
    DC_NEXTDEFSYM_RANGE = (20, 4)
    DC_IUNDEFSYM_RANGE = (24, 4)
    DC_NUNDEFSYM_RANGE = (28, 4)
    DC_TOCOFF_RANGE = (32, 4)
    DC_NTOC_RANGE = (36, 4)
    DC_MODTABOFF_RANGE = (40, 4)
    DC_NMODTAB_RANGE = (44, 4)
    DC_EXTREFSYMOFF_RANGE = (48, 4)
    DC_NEXTREFSYMS_RANGE = (52, 4)
    DC_INDIRECTSYMOFF_RANGE = (56, 4)
    DC_NINDIRECTSYMS_RANGE = (60, 4)
    DC_EXTRELOFF_RANGE = (64, 4)
    DC_NEXTREL_RANGE = (68, 4)
    DC_LOCRELOFF_RANGE = (72, 4)
    DC_NLOCREL_RANGE = (76, 4)

    def __init__(self):
        super().__init__()
        self.ilocalsym = 0
        self.nlocalsym = 0
        self.iextdefsym = 0
        self.nextdefsym = 0
        self.iundefsym = 0
        self.nundefsym = 0
        self.tocoff = 0
        self.ntoc = 0
        self.modtaboff = 0
        self.nmodtab = 0
        self.extrefsymoff = 0
        self.nextrefsyms = 0
        self.indirectsymoff = 0
        self.nindirectsyms = 0
        self.extreloff = 0
        self.nextrel = 0
        self.locreloff = 0
        self.nlocrel = 0

    @classmethod
    def parse_from_bytes(cls, _bytes):
        dc = cls()
        dc.cmd = parse_int(_bytes[0:4])
        dc.cmdsize = parse_int(_bytes[4:8])
        dc.ilocalsym = parse_int(_bytes[8:12])
        dc.nlocalsym = parse_int(_bytes[12:16])
        dc.iextdefsym = parse_int(_bytes[16:20])
        dc.nextdefsym = parse_int(_bytes[20:24])
        dc.iundefsym = parse_int(_bytes[24:28])
        dc.nundefsym = parse_int(_bytes[28:32])
        dc.tocoff = parse_int(_bytes[32:36])
        dc.ntoc = parse_int(_bytes[36:40])
        dc.modtaboff = parse_int(_bytes[40:44])
        dc.nmodtab = parse_int(_bytes[44:48])
        dc.extrefsymoff = parse_int(_bytes[48:52])
        dc.nextrefsyms = parse_int(_bytes[52:56])
        dc.indirectsymoff = parse_int(_bytes[56:60])
        dc.nindirectsyms = parse_int(_bytes[60:64])
        dc.extreloff = parse_int(_bytes[64:68])
        dc.nextrel = parse_int(_bytes[68:72])
        dc.locreloff = parse_int(_bytes[72:76])
        dc.nlocrel = parse_int(_bytes[76:80])
        return dc

    def get_size(self):
        return DysymtabCommand.DC_TOTAL_SIZE


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
        self.sections = {}

    @classmethod
    def parse_from_bytes(cls, _bytes):
        sc = cls()
        sc.cmd = parse_int(_bytes[0:4])
        sc.cmdsize = parse_int(_bytes[4:8])
        sc.segname = parse_str(_bytes[8:24])
        sc.vmaddr = parse_int(_bytes[24:28])
        sc.vmsize = parse_int(_bytes[28:32])
        sc.fileoff = parse_int(_bytes[32:36])
        sc.filesize = parse_int(_bytes[36:40])
        sc.maxprot = parse_int(_bytes[40:44])
        sc.initprot = parse_int(_bytes[44:48])
        sc.nsects = parse_int(_bytes[48:52])
        sc.flags = parse_int(_bytes[52:56])
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
        sc64.cmd = parse_int(_bytes[0:4])
        sc64.cmdsize = parse_int(_bytes[4:8])
        sc64.segname = parse_str(_bytes[8:24])
        sc64.vmaddr = parse_int(_bytes[24:32])
        sc64.vmsize = parse_int(_bytes[32:40])
        sc64.fileoff = parse_int(_bytes[40:48])
        sc64.filesize = parse_int(_bytes[48:56])
        sc64.maxprot = parse_int(_bytes[56:60])
        sc64.initprot = parse_int(_bytes[60:64])
        sc64.nsects = parse_int(_bytes[64:68])
        sc64.flags = parse_int(_bytes[68:72])
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
        section.sectname = parse_str(_bytes[0:16])
        section.segname = parse_str(_bytes[16:32])
        section.addr = parse_int(_bytes[32:36])
        section.size = parse_int(_bytes[36:40])
        section.offset = parse_int(_bytes[40:44])
        section.align = parse_int(_bytes[44:48])
        section.reloff = parse_int(_bytes[48:52])
        section.nreloc = parse_int(_bytes[52:56])
        section.flags = parse_int(_bytes[56:60])
        section.reserved1 = parse_int(_bytes[60:64])
        section.reserved2 = parse_int(_bytes[64:68])
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
        section.sectname = parse_str(_bytes[0:16])
        section.segname = parse_str(_bytes[16:32])
        section.addr = parse_int(_bytes[32:40])
        section.size = parse_int(_bytes[40:48])
        section.offset = parse_int(_bytes[48:52])
        section.align = parse_int(_bytes[52:56])
        section.reloff = parse_int(_bytes[56:60])
        section.nreloc = parse_int(_bytes[60:64])
        section.flags = parse_int(_bytes[64:68])
        section.reserved1 = parse_int(_bytes[68:72])
        section.reserved2 = parse_int(_bytes[72:76])
        section.reserved3 = parse_int(_bytes[76:80])
        return section

    def get_size(self):
        return Section.S_TOTAL_SIZE
