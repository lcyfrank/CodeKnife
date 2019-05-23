from utils import *
# The `cpu_type_t` value for Mach-O header
# https://opensource.apple.com/source/cctools/cctools-836/include/mach/machine.h
CPU_TYPE_ARM = 0xc
CPU_TYPE_ARM64 = 0x100000c
CPU_TYPE_I386 = 0x1000007
CPU_TYPE_X86_64 = CPU_TYPE_I386

# BIND OPTIONS
BIND_TYPE_POINTER = 1
BIND_TYPE_TEXT_ABSOLUTE32 = 2
BIND_TYPE_TEXT_PCREL32 = 3

BIND_SPECIAL_DYLIB_SELF = 0
BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE = -1
BIND_SPECIAL_DYLIB_FLAT_LOOKUP = -2

BIND_SYMBOL_FLAGS_WEAK_IMPORT = 0x1
BIND_SYMBOL_FLAGS_NON_WEAK_DEFINITION = 0x8

BIND_OPCODE_MASK = 0xF0
BIND_IMMEDIATE_MASK = 0x0F
BIND_OPCODE_DONE = 0x00
BIND_OPCODE_SET_DYLIB_ORDINAL_IMM = 0x10
BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB = 0x20
BIND_OPCODE_SET_DYLIB_SPECIAL_IMM = 0x30
BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM = 0x40
BIND_OPCODE_SET_TYPE_IMM = 0x50
BIND_OPCODE_SET_ADDEND_SLEB = 0x60
BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB = 0x70
BIND_OPCODE_ADD_ADDR_ULEB = 0x80
BIND_OPCODE_DO_BIND = 0x90
BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB = 0xA0
BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED = 0xB0
BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB = 0xC0


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

    LC_REQ_DYLD = 0x80000000
    LC_SEGMENT = 0x1
    LC_SYMTAB = 0x2
    LC_DYSYMTAB = 0xb
    LC_LOAD_DYLIB = 0xc
    LC_SEGMENT_64 = 0x19
    LC_DYLD_INFO = 0x22
    LC_DYLD_INFO_ONLY = (0x22 | LC_REQ_DYLD)

    LC_LOAD_WEAK_DYLIB = (0x18 | LC_REQ_DYLD)
    LC_RPATH = (0x1c | LC_REQ_DYLD)

    def __init__(self):
        self.cmd = 0
        self.cmdsize = 0

    @classmethod
    def parse_from_bytes(cls, _bytes):
        lc = cls()
        lc.cmd = parse_int(_bytes[0:4])
        lc.cmdsize = parse_int(_bytes[4:8])
        return lc

    @classmethod
    def parse_from_dict(cls, lc_dict):
        cmd = lc_dict['cmd']
        if cmd == cls.LC_SEGMENT:
            return SegmentCommand.parse_from_dict(lc_dict)
        elif cmd == cls.LC_SYMTAB:
            return SymtabCommand.parse_from_dict(lc_dict)
        elif cmd == cls.LC_DYSYMTAB:
            return DysymtabCommand.parse_from_dict(lc_dict)
        elif cmd == cls.LC_LOAD_DYLIB:
            return LoadDylibCommand.parse_from_dict(lc_dict)
        elif cmd == cls.LC_SEGMENT_64:
            return SegmentCommand64.parse_from_dict(lc_dict)
        elif cmd == cls.LC_DYLD_INFO:
            return DyldInfoCommand.parse_from_dict(lc_dict)
        elif cmd == cls.LC_DYLD_INFO_ONLY:
            return DyldInfoCommand.parse_from_dict(lc_dict)
        elif cmd == cls.LC_LOAD_WEAK_DYLIB:
            return LoadDylibCommand.parse_from_dict(lc_dict)
        elif cmd == cls.LC_RPATH:
            return RpathCommand.parse_from_dict(lc_dict)
        else:
            cmd_object = LoadCommand()
            cmd_object.cmd = lc_dict['cmd']
            cmd_object.cmdsize = lc_dict['cmdsize']
            return cmd_object

    def get_size(self):
        return LoadCommand.LC_TOTAL_SIZE

    def convert_to_dict(self):
        return self.__dict__.copy()


class RpathCommand(LoadCommand):
    RC_TOTAL_SIZE = 12
    RC_PATH_RANGE = (8, 4)

    def __init__(self):
        super(RpathCommand, self).__init__()
        self.path = 0

    @classmethod
    def parse_from_bytes(cls, _bytes):
        rc = cls()
        rc.cmd = parse_int(_bytes[0:4])
        rc.cmdsize = parse_int(_bytes[4:8])
        rc.path = parse_int(_bytes[8:12])
        return rc

    @classmethod
    def parse_from_dict(cls, lc_dict):
        rc = cls()
        rc.__dict__ = lc_dict.copy()
        return rc

    def get_size(self):
        return RpathCommand.RC_TOTAL_SIZE


class DyldInfoCommand(LoadCommand):

    DIC_TOTAL_SIZE = 48
    DIC_REBASE_OFF_RANGE = (8, 4)
    DIC_REBASE_SIZE_RANGE = (12, 4)
    DIC_BIND_OFF_RANGE = (16, 4)
    DIC_BIND_SIZE_RANGE = (20, 4)
    DIC_WEAK_BIND_OFF_RANGE = (24, 4)
    DIC_WEAK_BIND_SIZE_RANGE = (28, 4)
    DIC_LAZY_BIND_OFF_RANGE = (32, 4)
    DIC_LAZY_BIND_SIZE_RANGE = (36, 4)
    DIC_EXPORT_OFF_RANGE = (40, 4)
    DIC_EXPORT_SIZE_RANGE = (44, 4)

    def __init__(self):
        super().__init__()
        self.rebase_off = 0
        self.rebase_size = 0
        self.bind_off = 0
        self.bind_size = 0
        self.weak_bind_off = 0
        self.weak_bind_size = 0
        self.lazy_bind_off = 0
        self.lazy_bind_size = 0
        self.export_off = 0
        self.export_size = 0

    @classmethod
    def parse_from_bytes(cls, _bytes):
        dic = cls()
        dic.cmd = parse_int(_bytes[0:4])
        dic.cmdsize = parse_int(_bytes[4:8])
        dic.rebase_off = parse_int(_bytes[8:12])
        dic.rebase_size = parse_int(_bytes[12:16])
        dic.bind_off = parse_int(_bytes[16:20])
        dic.bind_size = parse_int(_bytes[20:24])
        dic.weak_bind_off = parse_int(_bytes[24:28])
        dic.weak_bind_size = parse_int(_bytes[28:32])
        dic.lazy_bind_off = parse_int(_bytes[32:36])
        dic.lazy_bind_size = parse_int(_bytes[36:40])
        dic.export_off = parse_int(_bytes[40:44])
        dic.export_size = parse_int(_bytes[44:48])
        return dic

    @classmethod
    def parse_from_dict(cls, dic_dict):
        dic = cls()
        dic.__dict__ = dic_dict.copy()
        return dic

    def get_size(self):
        return DyldInfoCommand.DIC_TOTAL_SIZE


class LoadDylibCommand(LoadCommand):

    LDC_TOTAL_SIZE = 24
    LDC_DYLIB_RANGE = (8, 16)

    def __init__(self):
        self.dylib = None

    @classmethod
    def parse_from_bytes(cls, _bytes):
        dc = cls()
        dc.cmd = parse_int(_bytes[0:4])
        dc.cmdsize = parse_int(_bytes[4:8])
        dc.dylib = Dylib.parse_from_bytes(_bytes[8:24])
        return dc

    @classmethod
    def parse_from_dict(cls, dc_dict):
        dc = cls()
        dc.__dict__ = dc_dict.copy()
        dc.dylib = Dylib.parse_from_dict(dc_dict['dylib'])
        return dc

    def get_size(self):
        return LoadDylibCommand.LDC_TOTAL_SIZE

    def convert_to_dict(self):
        ldc_dict = self.__dict__.copy()
        ldc_dict['dylib'] = self.dylib.__dict__.copy()
        return ldc_dict


class Dylib:

    D_TOTAL_SIZE = 16
    D_NAME_RANGE = (0, 4)
    D_TIMESTAMP_RANGE = (4, 4)
    D_CURRENT_VERSION_RANGE = (8, 4)
    D_COMPATIBILITY_VERSION_RANGE = (12, 4)

    def __init__(self):
        self.name = 0
        self.timestamp = 0
        self.current_version = 0
        self.compatibility_version = 0

    @classmethod
    def parse_from_bytes(cls, _bytes):
        dylib = cls()
        dylib.name = parse_int(_bytes[0:4])
        dylib.timestamp = parse_int(_bytes[4:8])
        dylib.current_version = parse_int(_bytes[8:12])
        dylib.compatibility_version = parse_int(_bytes[12:16])
        return dylib

    @classmethod
    def parse_from_dict(cls, d_dict):
        dylib = cls()
        dylib.__dict__ = d_dict.copy()
        return dylib

    def get_size(self):
        return Dylib.D_TOTAL_SIZE


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

    @classmethod
    def parse_from_dict(cls, sc_dict):
        sc = cls()
        sc.__dict__ = sc_dict.copy()
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

    @classmethod
    def parse_from_dict(cls, dc_dict):
        dc = cls()
        dc.__dict__ = dc_dict.copy()
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

    @classmethod
    def parse_from_dict(cls, sc_dict):
        sc = cls()
        sc.__dict__ = sc_dict.copy()
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

    @classmethod
    def parse_from_dict(cls, sc64_dict):
        sc64 = cls()
        sc64.__dict__ = sc64_dict.copy()
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

    @classmethod
    def parse_from_dict(cls, section_dict):
        section = cls()
        section.__dict__ = section_dict.copy()
        return section

    def get_size(self):
        return Section.S_TOTAL_SIZE

    def convert_to_dict(self):
        return self.__dict__.copy()


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

    @classmethod
    def parse_from_dict(cls, section_dict):
        section = cls()
        section.__dict__ = section_dict.copy()
        return section

    def get_size(self):
        return Section64.S_TOTAL_SIZE

    def convert_to_dict(self):
        return self.__dict__.copy()
