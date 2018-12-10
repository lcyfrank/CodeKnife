from capstone import *
from capstone.arm64 import *
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


def parse_int_from_bytes(buffer, begin, length, little=True):
    '''Parse the integer from given bytes.

    Args:
        buffer: given bytes
        begin: begin point in given bytes
        length: length of parsing part of bytes
        little: is little end
    '''
    if little:
        temp_buffer = b''
        for i in range(begin, begin + length):
            temp_buffer = buffer[i: i + 1] + temp_buffer
        return int(temp_buffer.hex(), 16)
    return int(buffer[begin: begin + length].hex(), 16)


def parse_str_from_bytes(buffer, begin, length):
    return buffer[begin:begin + length].decode('utf-8')


def parse_fat_binary_if_should(buffer):
    '''Parse the Fat header of Mach-O file.

    Reference: https://opensource.apple.com/source/xnu/xnu-792/EXTERNAL_HEADERS/mach-o/fath.auto.html

    Args:
        buffer: given bytes
    '''
    fh_field_size = 4  # the size of each field in fat_header
    fh_number_offset = 4  # the `number` field offset in fat_header
    fh_size = 8  # the size of total fat_header

    if not buffer.startswith(b'\xca\xfe\xba\xbe'):
        # Check if current is fat binary
        # Fat binary is begin with 0xcafebabe
        print("Current file is not fat binary")
        return None

    offset = fh_number_offset
    end = fh_number_offset + fh_field_size
    nfat_arch = int(mach_o_content_bytes[offset:end].hex(), 16)

    fa_base = fh_size  # the base address of fat_archs
    fa_field_size = 4  # the size of each field in fat_arch
    fa_size = 20  # the size of total fat_arch

    fat_archs = []
    for fat_num in range(nfat_arch):
        parse_values = []
        for j in range(5):
            begin = fa_base + fat_num * fa_size + fa_field_size * j
            length = fa_field_size
            parse_values.append(parse_int_from_bytes(
                buffer, begin, length, False))
        fat_archs.append({
            FA_CPU_TYPE_KEY: parse_values[0],
            FA_CPU_SUBTYPE_KEY: parse_values[1],
            FA_OFFSET_KEY: parse_values[2],
            FA_SIZE_KEY: parse_values[3],
            FA_ALIGN_KEY: parse_values[4]
        })
    return fat_archs


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

    model = None
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

        text_addr = (text_section.addr if mach_header.magic ==
                     MachHeader.MH_MAGIC_32 else (text_section.addr - 0x100000000))
        text_size = text_section.size
        machine_code = mach_o_content_bytes[text_addr: text_addr + text_size]

        # WARNING!!!
        # 如果机器码太多，反编译过程会中断，不知道为啥
        for (address, size, mnemonic, op_str) in model.disasm_lite(machine_code, text_section.addr):
            # TODO: 找到函数边界（可以通过 capstone 提供的指令类型）
            # print(address)
            print(mnemonic)
            # pass

            # Reference:
            # > https://zhuanlan.zhihu.com/p/24858664
