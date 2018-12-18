from capstone import *
from capstone.arm64 import *
from capstone.arm import *
from capstone.x86 import *
from mach_o_info import *
from objc_runtime import *
from utils import *
from fat_info import *

# TEST_PATH = './Test'
TEST_PATH = './Target/HotPatchDemo'
# TEST_PATH = './Target/pinduoduo'


# Constant
FA_CPU_TYPE_KEY = 'cputype'
FA_CPU_SUBTYPE_KEY = 'cpu_subtype'
FA_OFFSET_KEY = 'offset'
FA_SIZE_KEY = 'size'
FA_ALIGN_KEY = 'align'


def parse_fat_binary_if_should(buffer):
    '''Parse the Fat header of Mach-O file.

    Reference: https://opensource.apple.com/source/xnu/xnu-792/EXTERNAL_HEADERS/mach-o/fath.auto.html

    Args:
        buffer: given bytes
    '''

    if not buffer.startswith(b'\xca\xfe\xba\xbe'):
        # Check if current is fat binary
        # Fat binary is begin with 0xcafebabe
        print("Current file is not fat binary")
        return None

    header = FatHeader.parse_from_bytes(buffer[0:FatHeader.FH_TOTAL_SIZE])
    nfat_arch = header.nfat_arch

    fat_archs = []
    for i in range(nfat_arch):
        fat_arch_begin = header.get_size() + i * FatArch.FA_TOTAL_SIZE
        fat_arch = FatArch.parse_from_bytes(
            buffer[fat_arch_begin:fat_arch_begin + FatArch.FA_TOTAL_SIZE])
        fat_archs.append(fat_arch)
    return fat_archs


def _slice_by_function_for_arm64(model, machine_code, base_addr):
    functions = []
    current_function = []
    function_over = False
    for insn in model.disasm(machine_code, base_addr):
        if not function_over:
            current_function.append(insn)
            if (insn.id == ARM64_INS_RET):
                function_over = True
                functions.append(current_function)
        else:
            current_function = []
            function_over = False
            current_function.append(insn)
    return functions


def parse_out_symtab(buffer, offset=0x0):
    '''parse `symtab` field of given buffer
    '''
    load_cmd_bytes = buffer[offset:offset + LoadCommand.LC_TOTAL_SIZE]
    load_cmd = LoadCommand.parse_from_bytes(load_cmd_bytes)
    if load_cmd.cmd != LoadCommand.LC_SYMTAB:
        return None
    else:
        load_cmd_bytes = buffer[offset:offset + SymtabCommand.SC_TOTAL_SIZE]
        symtab = SymtabCommand.parse_from_bytes(load_cmd_bytes)
        return symtab


def parse_out_dysymtab(buffer, offset=0x0):

    load_cmd_bytes = buffer[offset: offset + LoadCommand.LC_TOTAL_SIZE]
    load_cmd = LoadCommand.parse_from_bytes(load_cmd_bytes)
    if load_cmd.cmd != LoadCommand.LC_DYSYMTAB:
        return None
    else:
        load_cmd_bytes = buffer[offset:offset + DysymtabCommand.DC_TOTAL_SIZE]
        dysymtab = DysymtabCommand.parse_from_bytes(load_cmd_bytes)
        return dysymtab


def parse_out_segment(buffer, offset=0x0):
    '''parse `segment` command of given buffer
    '''
    load_cmd_bytes = buffer[offset:offset + LoadCommand.LC_TOTAL_SIZE]
    load_cmd = LoadCommand.parse_from_bytes(load_cmd_bytes)
    if load_cmd.cmd != LoadCommand.LC_SEGMENT:
        return None
    else:
        load_cmd_bytes = buffer[offset:offset + SegmentCommand.SC_TOTAL_SIZE]
        segment = SegmentCommand.parse_from_bytes(load_cmd_bytes)
        return segment


def parse_out_segment64(buffer, offset=0x0):
    '''parse `segment64` command of given buffer
    '''
    load_cmd_bytes = buffer[offset:offset + LoadCommand.LC_TOTAL_SIZE]
    load_cmd = LoadCommand.parse_from_bytes(load_cmd_bytes)
    if load_cmd.cmd != LoadCommand.LC_SEGMENT_64:
        return None
    else:
        load_cmd_bytes = buffer[offset:offset + SegmentCommand64.SC_TOTAL_SIZE]
        segment64 = SegmentCommand64.parse_from_bytes(load_cmd_bytes)
        return segment64


def parse_out_commands(buffer, offset=0x0):

    commands = {}

    header = None
    if (buffer.startswith(b'\xce\xfa\xed\xfe')):
        # 32-bit
        mach_header_bytes = buffer[0:MachHeader.MH_TOTAL_SIZE]
        header = MachHeader.parse_from_bytes(mach_header_bytes)
    elif (buffer.startswith(b'\xcf\xfa\xed\xfe')):
        # 64-bit
        mach_header_bytes = buffer[0:MachHeader64.MH_TOTAL_SIZE]
        header = MachHeader64.parse_from_bytes(mach_header_bytes)
    else:
        print("Current file is not Mach-O binary")
        return None
    print('Found the Mach-O file')

    lc_pointer = header.get_size()
    for _ in range(header.ncmds):

        load_cmd_bytes = buffer[lc_pointer:lc_pointer +
                                LoadCommand.LC_TOTAL_SIZE]
        load_cmd = LoadCommand.parse_from_bytes(load_cmd_bytes)

        # parse `symtab` command
        if load_cmd.cmd == LoadCommand.LC_SYMTAB:
            load_cmd = parse_out_symtab(buffer, lc_pointer)
            commands["symtab"] = load_cmd
        elif load_cmd.cmd == LoadCommand.LC_DYSYMTAB:
            load_cmd = parse_out_dysymtab(buffer, lc_pointer)
            commands["dysymtab"] = load_cmd
        # parse `segment` command
        elif load_cmd.cmd == LoadCommand.LC_SEGMENT:
            load_cmd = parse_out_segment(buffer, lc_pointer)
            sections = parse_out_sections(
                load_cmd, buffer, lc_pointer + load_cmd.get_size())
            load_cmd.sections = sections
            if "segment" in commands:
                commands["segment"][load_cmd.segname] = load_cmd
            else:
                commands["segment"] = {}
                commands["segment"][load_cmd.segname] = load_cmd
        # parse `segment64` command
        elif load_cmd.cmd == LoadCommand.LC_SEGMENT_64:
            load_cmd = parse_out_segment64(buffer, lc_pointer)
            sections = parse_out_sections(
                load_cmd, buffer, lc_pointer + load_cmd.get_size())
            load_cmd.sections = sections
            if "segment64" in commands:
                commands["segment64"][load_cmd.segname] = load_cmd
            else:
                commands["segment64"] = {}
                commands["segment64"][load_cmd.segname] = load_cmd
        else:
            pass

        lc_pointer += load_cmd.cmdsize
    commands['mach_header'] = header
    print('Parse specified load command from `Mach-O` file complete!')
    return commands


def parse_out_sections(segment, buffer, offset):

    sections = {}

    if (type(segment) != SegmentCommand and
            type(segment) != SegmentCommand64):
        print("Not Segment Command")
    else:
        if segment.segname.startswith('__TEXT'):
            print("Found the `__TEXT` segment")
        elif segment.segname.startswith('__DATA'):
            print("Found the `__DATA` segment")
        elif segment.segname.startswith('__PAGEZERO'):
            print("Found the `__PAGEZERO` segment")

        is_64_bit = type(segment) == SegmentCommand64
        section_pointer = offset
        for _ in range(segment.nsects):
            section = None
            if is_64_bit:
                section_bytes = buffer[section_pointer: section_pointer +
                                       Section64.S_TOTAL_SIZE]
                section = Section64.parse_from_bytes(section_bytes)
            else:
                section_bytes = buffer[section_pointer: section_pointer +
                                       Section.S_TOTAL_SIZE]
                section = Section.parse_from_bytes(section_bytes)

            if section.sectname.startswith('__text'):
                print("Found the `__text` section")
                sections['text'] = section
            elif section.sectname.startswith('__stubs'):
                print("Found the `__stubs` section")
                sections['stubs'] = section
            elif section.sectname.startswith('__la_symbol_ptr'):
                print("Found the `__la_symbol_ptr` section")
                sections['la_symbol_ptr'] = section
            elif section.sectname.startswith('__objc_selrefs'):
                print("Found the `__objc_selrefs` section")
                sections['objc_selrefs'] = section
            elif section.sectname.startswith('__objc_methname'):
                print("Found the `__objc_methname` section")
                sections['objc_methname'] = section
            elif section.sectname.startswith('__objc_classlist'):
                print("Found the `__objc_classlist` section")
                sections['objc_classlist'] = section

            section_pointer += section.get_size()
    return sections


if __name__ == "__main__":
    is_fat_binary = False
    seek_p = 0

    mach_o_file = open(TEST_PATH, 'rb')
    mach_o_content_bytes = mach_o_file.read()
    fat_archs = parse_fat_binary_if_should(mach_o_content_bytes)
    mach_infos = []
    if fat_archs == None:
        is_fat_binary = False
        commands = parse_out_commands(mach_o_content_bytes)
        mach_infos.append(commands)
    else:
        is_fat_binary = True
        for fat_arch in fat_archs:
            begin = fat_arch.offset
            size = fat_arch.size
            commands = parse_out_commands(
                mach_o_content_bytes[begin:begin + size], begin)
            mach_infos.append(commands)

    for i in range(len(mach_infos)):
        mach_info = mach_infos[i]
        mach_header = mach_info['mach_header']
        is_64_bit = type(mach_header) == MachHeader64

        symtab = mach_info['symtab']
        dysymtab = mach_info['dysymtab']

        segments_key = 'segment'
        if is_64_bit:
            segments_key += '64'
        segments = mach_info[segments_key]

        # ===================== Parse out the symbol table =====================
        # =================== same between 32-bit and 64-bit ===================
        # ====================== produce `symbol_tables` =======================
        # ====================== produce `symbol_names` ========================
        symbol_table = []
        symbol_names = {}
        begin_pointer = symtab.symoff
        nlist_size = Nlist64.N_TOTAL_SIZE if is_64_bit else Nlist.N_TOTAL_SIZE
        for _ in range(symtab.nsyms):
            nlist_bytes = mach_o_content_bytes[begin_pointer:begin_pointer + nlist_size]

            nlist = (Nlist64.parse_from_bytes(nlist_bytes) if is_64_bit
                     else Nlist.parse_from_bytes(nlist_bytes))

            name_begin = nlist.n_strx + symtab.stroff
            name_end = mach_o_content_bytes.find(b'\x00', name_begin + 1)
            name_bytes = mach_o_content_bytes[name_begin:name_end]
            name = parse_str(name_bytes)
            symbol_table.append(nlist)
            symbol_names[str(nlist.n_strx)] = name
            begin_pointer += nlist.get_size()

        # ==================== Initialize the DISASM model =====================
        # ================= depend on specified architectures ==================
        # ========================== produce `model` ===========================
        arch = CS_ARCH_ALL
        mode = CS_MODE_32
        if mach_header.cputype == CPU_TYPE_ARM:
            arch = CS_ARCH_ARM
            mode = CS_MODE_THUMB
        elif mach_header.cputype == CPU_TYPE_ARM64:
            arch = CS_ARCH_ARM64
            mode = CS_MODE_ARM
        elif mach_header.cputype == CPU_TYPE_X86_64:
            arch = CS_ARCH_X86
            mode = CS_MODE_32 if not is_64_bit else CS_MODE_64

        model = Cs(arch, mode)
        model.detail = True

        # ===================== Slice the stubs functions ======================
        # ========================== for 64-bit only ===========================
        # ===================== produce `stubs_functions` ======================
        stubs_functions = {}
        method_name = []
        objc_methname = None
        segment = segments['__TEXT']
        stubs = segment.sections['stubs']
        indirectsymoff = dysymtab.indirectsymoff
        offset = stubs.reserved1
        total_size = stubs.size
        each_size = stubs.reserved2
        count = 0
        while count < int(total_size / each_size):
            index_begin = indirectsymoff + (count + offset) * 4
            index_bytes = mach_o_content_bytes[index_begin:index_begin + 4]
            index = parse_int(index_bytes)
            nlist = symbol_table[index]
            stubs_key = hex(stubs.addr + count * each_size)
            stubs_functions[stubs_key] = symbol_names[str(
                nlist.n_strx)]
            count += 1

        # ======================= Parse out all classes ========================
        # ========================== for 64-bit only ===========================
        # ===================== produce `stubs_functions` ======================
        segment = segments['__DATA']
        objc_classlist = segment.sections['objc_classlist']
        classlist_addr = (objc_classlist.addr if not is_64_bit
                          else objc_classlist.addr - 0x100000000)
        total_size = objc_classlist.size
        each_size = 8
        count = 0
        while count < int(total_size / each_size):
            classlist_begin = classlist_addr + count * each_size
            class_bytes = mach_o_content_bytes[classlist_begin:classlist_begin + each_size]
            oc_bytes_begin = (parse_int(class_bytes) if not is_64_bit
                              else parse_int(class_bytes) - 0x100000000)
            oc_bytes = mach_o_content_bytes[oc_bytes_begin:oc_bytes_begin+ObjcClass64.OC_TOTAL_SIZE]
            objc_class = ObjcClass64.parse_from_bytes(oc_bytes)
            print(hex(objc_class.data))
            count += 1

        #     objc_methname = segment.sections['objc_methname']

        # if segment.segname.startswith('__DATA'):
        #     objc_selrefs = segment.sections['objc_selrefs']
        #     selrefs_count = objc_selrefs.size / 8  # 8 is length of address
        #     count = 0
        #     while count < selrefs_count:
        #         name_addr_begin = (objc_selrefs.addr if not is_64_bit
        #                            else objc_selrefs.addr - 0x100000000)
        #         name_addr_begin += count * 8
        #         name_addr_bytes = mach_o_content_bytes[name_addr_begin:name_addr_begin + 8]
        #         name_addr = parse_int(name_addr_bytes)
        #         name_begin = (name_addr if not is_64_bit
        #                       else name_addr - 0x100000000)
        #         name_end = mach_o_content_bytes.find(
        #             b'\x00', name_begin + 1)
        #         name_bytes = mach_o_content_bytes[name_begin:name_end]
        #         name = parse_str(name_bytes)

        #         print(list(symbol_names.values()).index(name))

        #         method_name.append(name)
        #         count += 1

        # text = segment.sections['text']
        # text_begin = (text.addr if not is_64_bit
        #               else text.addr - 0x100000000)
        # text_code = mach_o_content_bytes[text_begin:text_begin + text.size]
        # method_instructions = _slice_by_function_for_arm64(
        #     model, text_code, text.addr)
        # for method in method_instructions:
        #     method_addr = method[0].address
        #     for nlist in symbol_table:
        #         if nlist.n_value == method_addr:
        #             # print(hex(method_addr))
        #             nlist.describe()
        #             # print(symbol_names[str(nlist.n_strx)])
        #             break
        # break

        # ======================= Generate call graphics =======================
        # ========================== for 64-bit only ===========================

        # elif segment.segname.startswith('__DATA'):
        #     la_symbol_ptr = segment.sections['la_symbol_ptr']
        #     la_symbol_ptr.describe()
        # print('la_symbol_ptr_section: ' + str(la_symbol_ptr.reserved1))

    #     mach_header = mach_info['mach_header']
    #     text_section = mach_info['text_section']
    #     stubs_section = mach_info['stubs_section']
        # la_symbol_ptr_section = mach_info['la_symbol_ptr']
        # print('la_symbol_ptr_section: ' + str(la_symbol_ptr_section.reserved1))

    #     arch = CS_ARCH_ALL
    #     mode = CS_MODE_32
    #     if mach_header.cputype == CPU_TYPE_ARM:
    #         arch = CS_ARCH_ARM
    #         mode = CS_MODE_THUMB
    #     elif mach_header.cputype == CPU_TYPE_ARM64:
    #         arch = CS_ARCH_ARM64
    #         mode = CS_MODE_ARM
    #     elif mach_header.cputype == CPU_TYPE_X86_64:
    #         arch = CS_ARCH_X86
    #         mode = (CS_MODE_32 if mach_header.magic ==
    #                 MachHeader.MH_MAGIC_32 else CS_MODE_64)
    #     model = Cs(arch, mode)
    #     model.detail = True

    #     text_addr = (text_section.addr if mach_header.magic ==
    #                  MachHeader.MH_MAGIC_32 else (text_section.addr - 0x100000000))
    #     text_size = text_section.size
    #     stubs_addr = (stubs_section.addr if mach_header.magic ==
    #                   MachHeader.MH_MAGIC_32 else (stubs_section.addr - 0x100000000))
    #     stubs_size = stubs_section.size
    #     la_symbol_ptr_addr = (la_symbol_ptr_section.addr if mach_header.magic ==
    #                           MachHeader.MH_MAGIC_32 else (la_symbol_ptr_section.addr - 0x100000000))
    #     la_symbol_ptr_size = la_symbol_ptr_section.size

    #     machine_code = mach_o_content_bytes[text_addr: text_addr + text_size]
    #     stubs_code = mach_o_content_bytes[stubs_addr: stubs_addr + stubs_size]
    #     la_symbol_ptr_code = mach_o_content_bytes[la_symbol_ptr_addr:
    #                                               la_symbol_ptr_addr + la_symbol_ptr_size]
    #     print(la_symbol_ptr_code.hex())

    #     for insn in model.disasm(la_symbol_ptr_code, la_symbol_ptr_section.addr):
    #         print("0x%s\t0x%s\t%s\t%s" % (hex(insn.address),
    #                                       insn.bytes.hex(), insn.mnemonic, insn.op_str))

        # WARNING!!!
        # 如果机器码太多，反编译过程会中断，不知道为啥
        # functions = _slice_by_function_for_arm64(
        #     model, machine_code, text_addr)

        # for function in functions:
        #     print('==========================================')
        #     for insn in function:
        #         print('0x%s\t0x%s\t%s\t%s' % (hex(insn.address),
        #                                       insn.bytes.hex(), insn.mnemonic, insn.op_str))
        # for insn in model.disasm(machine_code, text_section.addr):
        #     # TODO: 找到函数边界（可以通过 capstone 提供的指令id）
        #     # 以 64-bit 为例
        #     if not function_over:
        #         current_function.append(insn)
        #         if (insn.id == ARM64_INS_RET):
        #             function_over = True
        #             functions.append(current_function)
        #     else:
        #         current_function = []
        #         function_over = False
        #         current_function.append(insn)
        # print(functions)

        # ARM64_INS_ADC
        # id
        # address
        # size
        # bytes
        # mnemonic
        # op_str
        # regs_read
        # regs_write
        # groups
        # operands


# Reference:
# > https://zhuanlan.zhihu.com/p/24858664
