from capstone import *
from capstone.arm64 import *

TEST_PATH = './Test'
# TEST_PATH = './Target/pinduoduo'

# Constant
FA_CPU_TYPE_KEY = 'cputype'
FA_CPU_SUBTYPE_KEY = 'cpu_subtype'
FA_OFFSET_KEY = 'offset'
FA_SIZE_KEY = 'size'
FA_ALIGN_KEY = 'align'

def parse_int_from_bytes(buffer, begin, length, little = True):
    '''
    Parse the integer from given bytes
    > buffer: given bytes
    > begin: begin point in given bytes
    > length: length of parsing part of bytes
    > little: is little end
    '''
    if little:
        temp_buffer = b''
        for i in range(begin, begin + length):
            temp_buffer = buffer[i : i + 1] + temp_buffer    
        return int(temp_buffer.hex(), 16)
    return int(buffer[begin: begin + length].hex(), 16)

def parse_str_from_bytes(buffer, begin, length):
    return buffer[begin:begin + length].decode('utf-8')

def parse_fat_binary_if_should(buffer):
    '''
    Parse the Fat header of Mach-O file
    > buffer: given bytes

    Reference: https://opensource.apple.com/source/xnu/xnu-792/EXTERNAL_HEADERS/mach-o/fat.h.auto.html
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
            parse_values.append(parse_int_from_bytes(buffer, begin, length, False))
        fat_archs.append({
            FA_CPU_TYPE_KEY : parse_values[0], 
            FA_CPU_SUBTYPE_KEY : parse_values[1], 
            FA_OFFSET_KEY : parse_values[2],
            FA_SIZE_KEY : parse_values[3],
            FA_ALIGN_KEY : parse_values[4]
        })
    return fat_archs

def parse_text_from_mach(buffer, offset = 0x0):
    # mach header info
    mh_ncmds_offset = 16
    mh_ncmds_size = 4
    mh_size_32 = 28
    mh_size_64 = 32
    # load commander info
    lc_cmd_offset = 0
    lc_cmd_size = 4
    lc_cmdsize_offset = 4
    lc_cmdsize_size = 4
    # segment info
    seg_name_offset = 8
    seg_name_size = 16
    seg_nsects_offset_32 = 48
    seg_nsects_offset_64 = 64
    seg_nsects_size = 4
    seg_size_32 = 56
    seg_size_64 = 72
    # section info
    sec_name_offset = 0
    sec_name_size = 16
    sec_addr_offset = 32
    sec_addr_size_32 = 4
    sec_addr_size_64 = 8
    sec_size_offset_32 = 36
    sec_size_offset_64 = 40
    sec_size_size_32 = 4
    sec_size_size_64 = 8
    sec_size_32 = 68
    sec_size_64 = 80

    is_64_bit = False
    if (buffer.startswith(b'\xce\xfa\xed\xfe')):
        # 32-bit
        pass
    elif (buffer.startswith(b'\xcf\xfa\xed\xfe')):
        # 64-bit
        is_64_bit = True
    else:
        print("Current file is not Mach-O binary")
        return None
    # parse the number of load commanders
    LC_CMD_NUMBER = 25 if is_64_bit else 1
    ncmds = parse_int_from_bytes(buffer, mh_ncmds_offset, mh_ncmds_size)
    print(ncmds)
    cmds_pointer = mh_size_64 if is_64_bit else mh_size_32
    for _ in range(ncmds):
        cmd = parse_int_from_bytes(buffer, cmds_pointer + lc_cmd_offset, lc_cmd_size)
        cmdsize = parse_int_from_bytes(buffer, cmds_pointer + lc_cmdsize_offset, lc_cmdsize_size)
        if LC_CMD_NUMBER == cmd:
            segname_begin = cmds_pointer + seg_name_offset
            segname_length = seg_name_size
            segname = parse_str_from_bytes(buffer, segname_begin, segname_length)
            if segname.startswith('__TEXT'):
                nsects_begin = cmds_pointer + (seg_nsects_offset_64 if is_64_bit else seg_nsects_offset_32)
                nsects_length = seg_nsects_size
                # parse the number of sections
                nsects = parse_int_from_bytes(buffer, nsects_begin, nsects_length)
                sect_base = cmds_pointer + (seg_size_64 if is_64_bit else seg_size_32)
                for sect_number in range(nsects):
                    current_sect_addr = sect_base + sect_number * (sec_size_64 if is_64_bit else sec_size_32)
                    sectname_begin = current_sect_addr + sec_name_offset
                    sectname_length = sec_name_size
                    # parse the name of section
                    sectname = parse_str_from_bytes(buffer, sectname_begin, sectname_length)
                    if sectname.startswith('__text'):
                        textbase_begin = current_sect_addr + sec_addr_offset
                        textbase_length = sec_addr_size_64 if is_64_bit else sec_addr_size_32
                        textsize_begin = current_sect_addr + (sec_size_offset_64 if is_64_bit else sec_size_offset_32)
                        textsize_length = sec_size_size_64 if is_64_bit else sec_size_size_32
                        text_base = parse_int_from_bytes(buffer, textbase_begin, textbase_length)
                        text_size = parse_int_from_bytes(buffer, textsize_begin, textsize_length)
                        return (text_base, text_size)
        cmds_pointer += cmdsize

is_fat_binary = False
seek_p = 0

mach_o_file = open(TEST_PATH, 'rb')
mach_o_content_bytes = mach_o_file.read()
fat_archs = parse_fat_binary_if_should(mach_o_content_bytes)
machine_codes = []
if fat_archs == None:
    is_fat_binary = False
    (text_base, text_size) = parse_text_from_mach(mach_o_content_bytes)
    machine_codes.append(mach_o_content_bytes[text_base:text_base + text_size])
else:
    is_fat_binary = True
    for fat_arch in fat_archs:
        begin = fat_arch[FA_OFFSET_KEY]
        size = fat_arch[FA_SIZE_KEY]
        print('begin: %d\nsize: %d' %(begin, size))
        (text_base, text_size) = parse_text_from_mach(mach_o_content_bytes[begin:begin + size], begin)
        machine_codes.append(mach_o_content_bytes[text_base:text_base + text_size])
# 
print(machine_codes[0])
model = Cs(CS_ARCH_ARM, CS_MODE_ARM)
for (address, size, mnemonic, op_str) in model.disasm_lite(machine_codes[0], 0x1000):
    print("0x%x:\t%s\t%s" %(address, mnemonic, op_str))

# Reference:
# > https://zhuanlan.zhihu.com/p/24858664