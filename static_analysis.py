from capstone import *
from capstone.arm64 import *
from capstone.arm import *
from capstone.x86 import *
from mach_o_info import *

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


def parse_text_from_mach(buffer, offset=0x0):
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

        if (LoadCommand.LC_SEGMENT != load_cmd.cmd and
                LoadCommand.LC_SEGMENT_64 != load_cmd.cmd):
            lc_pointer += load_cmd.cmdsize
            continue

        is_64_bit = True
        if LoadCommand.LC_SEGMENT == load_cmd.cmd:  # 32-bit
            load_cmd_bytes = buffer[lc_pointer:lc_pointer +
                                    SegmentCommand.SC_TOTAL_SIZE]
            load_cmd = SegmentCommand.parse_from_bytes(load_cmd_bytes)
            is_64_bit = False
        else:  # 64-bit
            load_cmd_bytes = buffer[lc_pointer:lc_pointer +
                                    SegmentCommand64.SC_TOTAL_SIZE]
            load_cmd = SegmentCommand64.parse_from_bytes(load_cmd_bytes)

        # parse `__TEXT` segment
        if load_cmd.segname.startswith('__TEXT'):
            print('Found the `__TEXT` segment')
            section_pointer = lc_pointer + load_cmd.get_size()

            for __ in range(load_cmd.nsects):
                section = None
                if is_64_bit:
                    section_bytes = buffer[section_pointer:section_pointer +
                                           Section64.S_TOTAL_SIZE]
                    section = Section64.parse_from_bytes(section_bytes)

                else:
                    section_bytes = buffer[section_pointer:section_pointer +
                                           Section.S_TOTAL_SIZE]
                    section = Section.parse_from_bytes(section_bytes)

                # parse `__text` section
                if section.sectname.startswith('__text'):
                    print('Found the `__text` section')
                    return {
                        'mach_header': header,
                        'text_section': section
                    }
                section_pointer += section.get_size()
        lc_pointer += load_cmd.cmdsize
    print('Cannot find `__TEXT` segment or `__text` section')
    return None


if __name__ == "__main__":
    is_fat_binary = False
    seek_p = 0

    mach_o_file = open(TEST_PATH, 'rb')
    mach_o_content_bytes = mach_o_file.read()
    fat_archs = parse_fat_binary_if_should(mach_o_content_bytes)
    mach_infos = []
    if fat_archs == None:
        is_fat_binary = False
        parse_result = parse_text_from_mach(mach_o_content_bytes)
        mach_infos.append(parse_result)
    else:
        is_fat_binary = True
        for fat_arch in fat_archs:
            begin = fat_arch[FA_OFFSET_KEY]
            size = fat_arch[FA_SIZE_KEY]
            parse_result = parse_text_from_mach(
                mach_o_content_bytes[begin:begin + size], begin)
            mach_infos.append(parse_result)

    for i in range(len(mach_infos)):
        mach_info = mach_infos[i]
        mach_header = mach_info['mach_header']
        text_section = mach_info['text_section']

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
            mode = (CS_MODE_32 if mach_header.magic ==
                    MachHeader.MH_MAGIC_32 else CS_MODE_64)
        model = Cs(arch, mode)
        model.detail = True

        text_addr = (text_section.addr if mach_header.magic ==
                     MachHeader.MH_MAGIC_32 else (text_section.addr - 0x100000000))
        text_size = text_section.size
        machine_code = mach_o_content_bytes[text_addr: text_addr + text_size]

        # WARNING!!!
        # 如果机器码太多，反编译过程会中断，不知道为啥
        functions = _slice_by_function_for_arm64(
            model, machine_code, text_addr)

        for function in functions:
            print('==========================================')
            for insn in function:
                print('0x%s\t0x%s\t%s\t%s' % (hex(insn.address),
                                          insn.bytes.hex(), insn.mnemonic, insn.op_str))
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
