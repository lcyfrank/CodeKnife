from utils import *

from models.mach_o.fat import *
from models.mach_o.loader import *
from models.mach_o.nlist import *
from models.objc_runtime import *
from models.class_storage import *
from models.objc_method import objc_methods_return_type, objc_methods_arguments

SELF_POINTER = -0x1000000
CURRENT_SELECTOR = -0x2000000
RETURN_VALUE = -0x3000000


Analyse_32_Bit = 0
Analyse_64_Bit = 1
Analyse_Both = 2


class MachContainer:

    def __init__(self, _bytes=None, file_provider=None, mode=Analyse_64_Bit, mc_dict=None):

        if _bytes is not None:
            self.file_provider = file_provider
            self.bytes = _bytes
            self.is_fat = _bytes.startswith(b'\xca\xfe\xba\xbe')
            self.mach_objects = []
            self.nfat_arch = 0

            if self.is_fat:
                header = self.aple_header()
                self.nfat_arch = header.nfat_arch
                if mode == Analyse_32_Bit:  # just for 32-bit
                    for i in range(0, self.nfat_arch):
                        arch = self.aple_arch(i)
                        if arch.cputype == 0xc:  # ARM 32-bit
                            mach_bytes = self.bytes[arch.offset:arch.offset + arch.size]
                            mach_object = MachObject(mach_bytes, _offset=arch.offset, file_provider=self.file_provider)
                            self.mach_objects.append(mach_object)
                            break
                elif mode == Analyse_64_Bit:  # just for 64-bit
                    for i in range(0, self.nfat_arch):
                        arch = self.aple_arch(i)
                        if arch.cputype == 0x100000c:  # ARM 32-bit
                            mach_bytes = self.bytes[arch.offset:arch.offset + arch.size]
                            mach_object = MachObject(mach_bytes, _offset=arch.offset, file_provider=self.file_provider)
                            self.mach_objects.append(mach_object)
                            break
                else:  # analyse both
                    for i in range(0, self.nfat_arch):  # 两个都要
                        arch = self.aple_arch(i)
                        mach_bytes = self.bytes[arch.offset:arch.offset + arch.size]
                        mach_object = MachObject(mach_bytes, _offset=arch.offset, file_provider=self.file_provider)

                        self.mach_objects.append(mach_object)
            else:
                mach_object = MachObject(_bytes, file_provider=self.file_provider)
                self.mach_objects.append(mach_object)
        else:
            self.file_provider = None
            self.bytes = None
            self.is_fat = mc_dict['is_fat']
            self.nfat_arch = mc_dict['nfat_arch']
            self.mach_objects = []
            for mach_object_dict in mc_dict['mach_objects']:
                self.mach_objects.append(MachObject(mo_dict=mach_object_dict))

    def aple_header(self):
        header_bytes = self.bytes[0:FatHeader.FH_TOTAL_SIZE]
        return FatHeader.parse_from_bytes(header_bytes)

    def aple_arch(self, i):
        header = self.aple_header()
        if i < header.nfat_arch:
            fat_arch_begin = header.get_size() + i * FatArch.FA_TOTAL_SIZE
            fat_arch_end = fat_arch_begin + FatArch.FA_TOTAL_SIZE
            fat_arch_bytes = self.bytes[fat_arch_begin:fat_arch_end]
            return FatArch.parse_from_bytes(fat_arch_bytes)
        error = ("The index " + str(i) + " is beyond the "
                 "fat architecture's number which is " + str(self.nfat_arch) + ".")
        log_error(error)
        return None

    def convert_to_dict(self):
        mc_dict = {
            'is_fat': self.is_fat, 'nfat_arch': self.nfat_arch, 'mach_objects': []
        }
        for mach_info in self.mach_objects:
            mc_dict['mach_objects'].append(mach_info.convert_to_dict())
        return mc_dict


MachObjectTypeExecutable = 0
MachObjectTypeDylib = 1


class MachObject:

    def __init__(self, _bytes=None, _type=MachObjectTypeExecutable, _offset=0x0, file_provider=None, mo_dict=None):
        if _bytes is not None:
            self.type = _type
            self.file_provider = file_provider
            self.dylib_frameworks_path = []  # path names
            self.dylib_frameworks_mach = {}  # {path_name: macho} cache 动态库

            self.dylib_frameworks_pair = {}  # dylib_class: framework_path

            self.notification_handler = {}  # NSNotification 处理方法  {notification: [()]}
            self.notification_poster = {}  # NSNotification 发送的方法  {notification: [()]}

            self.bytes = _bytes
            self.offset = _offset
            self.is_64_bit = _bytes.startswith(b'\xcf\xfa\xed\xfe')
            header = self.aple_header()
            self.cpu_type = header.cputype
            self.cpu_subtype = header.cpusubtype
            self.file_type = header.filetype
            self.ncmds = header.ncmds

            self._cmds = self.aple_cmds()

            # 解析动态库
            for index, dylib_command in self._cmds['load_dylib']:
                # print(index)
                dylib = dylib_command.dylib
                name_begin = dylib.name
                name_end = _bytes.find(b'\x00', name_begin)
                name = parse_str(_bytes[name_begin:name_end])
                self.dylib_frameworks_path.append(name)

                # print(dylib_command.dylib)
            self._sections = self.aple_sections()

            self.text = self.generate_text()
            text_section, _ = self._sections['text']
            self.text_addr = text_section.addr  # 代码的内存（不是 offset）

            self.symbols = {}           # address: name
            self.ivar_refs = {}         # <> : index
            # self.property_refs = {}

            self.dylibs = {}            # ref_address: name
            self.functions = {}         # impaddr: symbol_address
            self.functions_type = []    # < function_data >
            self.statics = {}
            self.statics_class = {}     # static value: class_name
            self.ivars = {}             # ref_address: <ivar>
            # self.properties = {}

            # self.methods 中的方法均为开发人员实现的方法，包括类中的方法和分类中的方法
            self.class_methods = {}     # class_name: {method_name: address}
            self.methods = {}           # impaddr: (class, method)  / impaddr: (block, block)
            self.methods_type = {}      # (class, method): <method_data>

            self.class_name_address = {}  # name: data_address
            self.class_datas = {}       # data_address: < name, super_name, methods >
            self.cat_datas = {}         # data_address: < name, class_name, methods >

            # 解析 Block
            self.block_methods = {}     # data_address: <block_method_data>

            self.cfstrings = {}

            self.parse_dylib_class()
            # print(self.dylibs['0x10207e840'])
            # for key in self.dylibs:
            #     print(key, self.symbols[hex(self.dylibs[key])])

            self.parse_symtab()       # 修改成兼容 32-bit 和 64-bit
            self.parse_methname()
            self.parse_classname()
            self.parse_cstring()
            self.parse_methtype()

            self.parse_block()  # 解析 Block 需要依赖  dylib

            #  兼容 32-bit 和 64-bit
            if self.is_64_bit:
                self.parse_functions64()
            else:
                self.parse_functions()

            # self.parse_static()       # 修改成兼容 32-bit 和 64-bit

            self.parse_cfstring()
            self.parse_class_methods_and_data()
            self.parse_cat_methods_and_data()
            # print(self.dylib_frameworks_pair)
        else:
            self.functions_type = []

            self.type = mo_dict['type']
            self.dylib_frameworks_path = mo_dict['dylib_frameworks_path']
            self.dylib_frameworks_pair = mo_dict['dylib_frameworks_pair']
            self.notification_handler = mo_dict['notification_handler']
            self.notification_poster = mo_dict['notification_poster']
            self.offset = mo_dict['offset']
            self.is_64_bit = mo_dict['is_64_bit']
            self.cpu_type = mo_dict['cpu_type']
            self.cpu_subtype = mo_dict['cpu_subtype']
            self.file_type = mo_dict['file_type']
            self.ncmds = mo_dict['ncmds']
            self.text_addr = mo_dict['text_addr']
            self.symbols = mo_dict['symbols']
            self.dylibs = mo_dict['dylibs']
            self.functions = mo_dict['functions']
            self.statics = mo_dict['statics']
            self.statics_class = mo_dict['statics_class']

            self.class_methods = eval(mo_dict['class_methods'])
            self.methods = mo_dict['methods']
            self.class_name_address = mo_dict['class_name_address']
            self.cfstrings = mo_dict['cfstrings']
            self.ivar_refs = mo_dict['ivar_refs']
            self.ivars = mo_dict['ivars']

            self.bytes = mo_dict['bytes']
            self.text = mo_dict['text']

            self.dylib_frameworks_mach = {}
            for path_name in self.dylib_frameworks_mach:
                self.dylib_frameworks_mach[path_name] = MachObject(mo_dict=mo_dict['dylib_frameworks_mach'])

            self._cmds = {}
            for key in mo_dict['_cmds']:
                if key not in self._cmds:
                    self._cmds[key] = []
                for offset, cmd in mo_dict['_cmds'][key]:
                    self._cmds[key].append((offset, LoadCommand.parse_from_dict(cmd)))

            self._sections = {}
            for key in mo_dict['_sections']:
                section_dict, index = mo_dict['_sections'][key]
                if self.is_64_bit:
                    section = Section64.parse_from_dict(section_dict)
                else:
                    section = Section.parse_from_dict(section_dict)
                self._sections[key] = (section, index)

            self.methods_type = {}
            methods_type_dict = eval(mo_dict['methods_type'])
            for key in methods_type_dict:
                self.methods_type[key] = MethodData(md_dict=methods_type_dict[key])

            self.class_datas = {}
            for key in mo_dict['class_datas']:
                self.class_datas[key] = ClassData(cd_dict=mo_dict['class_datas'][key])

            self.cat_datas = {}
            for key in mo_dict['cat_datas']:
                self.cat_datas[key] = CatData(cd_dict=mo_dict['cat_datas'][key])

            self.block_methods = {}
            for key in mo_dict['block_methods']:
                self.block_methods[key] = BlockMethodData(bmd_dict=mo_dict['block_methods'][key])

    def post_notification(self, notification, poster, selector):
        if notification not in self.notification_poster:
            self.notification_poster[notification] = []
        self.notification_poster[notification].append((poster, selector))

    def add_notification_observer(self, notification, observer, selector):
        if notification not in self.notification_handler:
            self.notification_handler[notification] = []
        self.notification_handler[notification].append((observer, selector))

    def get_dylib_frameworks(self, framework_path):

        if framework_path in self.dylib_frameworks_mach:
            return self.dylib_frameworks_mach[framework_path]

        if "load_rpath" not in self._cmds:
            return None

        rpath_cmd = self._cmds["load_rpath"]
        rpaths = []
        for _, cmd in rpath_cmd:
            path_begin = cmd.path
            path_end = self.bytes.find(b'\x00', path_begin)
            path = parse_str(self.bytes[path_begin: path_end])

            if path.startswith('@executable_path'):
                rpaths.append(path[17:])

        if framework_path.startswith('@rpath'):
            dylib_framework_path = rpaths[0] + framework_path[6:]
            if self.file_provider:
                dylib_macho_file = self.file_provider(dylib_framework_path)
                file_bytes = dylib_macho_file.read()

                if file_bytes.startswith(b'\xca\xfe\xba\xbe'):  # Fat
                    header_bytes = file_bytes[0:FatHeader.FH_TOTAL_SIZE]
                    header = FatHeader.parse_from_bytes(header_bytes)
                    nfat_arch = header.nfat_arch
                    for i in range(0, nfat_arch):
                        fat_arch_begin = header.get_size() + i * FatArch.FA_TOTAL_SIZE
                        fat_arch_end = fat_arch_begin + FatArch.FA_TOTAL_SIZE
                        fat_arch_bytes = file_bytes[fat_arch_begin:fat_arch_end]
                        arch = FatArch.parse_from_bytes(fat_arch_bytes)
                        if self.is_64_bit and arch.cputype == 0x100000c:
                            dylib_macho_bytes = file_bytes[arch.offset:arch.offset + arch.size]
                            dylib_macho = MachObject(dylib_macho_bytes, _type=MachObjectTypeDylib, _offset=arch.offset)
                            self.dylib_frameworks_mach[framework_path] = dylib_macho
                            return dylib_macho
                        if not self.is_64_bit and arch.cputype == 0xc:
                            dylib_macho_bytes = file_bytes[arch.offset:arch.offset + arch.size]
                            dylib_macho = MachObject(dylib_macho_bytes, _type=MachObjectTypeDylib, _offset=arch.offset)
                            self.dylib_frameworks_mach[framework_path] = dylib_macho
                            return dylib_macho
                else:
                    dylib_macho_bytes = file_bytes
                    dylib_macho = MachObject(dylib_macho_bytes, _type=MachObjectTypeDylib)
                    self.dylib_frameworks_mach[framework_path] = dylib_macho
                    return dylib_macho
        return None

    # 从本二进制文件中得到方法地址
    def get_method_address(self, class_name, method_name):
        if class_name in self.class_methods:
            class_method = self.class_methods[class_name]
            if method_name in class_method:
                return class_method[method_name]
        return None

    def get_memory_content(self, address, size):
        address_key = hex(address)
        if address_key in self.dylibs:
            return True, self.dylibs[address_key]
        elif address_key in self.functions:
            return True, self.functions[address_key]
        elif address_key in self.ivars:
            return True, self.ivars[address_key]
        elif address_key in self.statics:
            return True, self.statics[address_key]
        else:
            if hex(address - SELF_POINTER) in self.ivar_refs:
                return True, self.ivar_refs[hex(address - SELF_POINTER)]
            else:
                if self.type == MachObjectTypeExecutable:
                    if self.is_64_bit:
                        address = address - 0x100000000
                    else:
                        address = address - self.offset  # 因为这个 32-bit 的 address 是相对于整个文件的
                    return False, parse_int(self.bytes[address:address + size])
                else:
                    return False, parse_int(self.bytes[address:address + size])

    def generate_text(self):
        text, _ = self._sections['text']
        if self.type == MachObjectTypeExecutable:
            text_begin = (
                    text.addr - self.offset if not self.is_64_bit else text.addr - 0x100000000)
        else:
            text_begin = text.offset

        text_code = self.bytes[text_begin:text_begin + text.size]
        return text_code

    def get_property_of_class(self, _class, name):
        if _class in self.class_name_address:
            class_address = self.class_name_address[_class]
            class_data = self.class_datas[hex(class_address)]
            for _property in class_data.properties:
                if _property.name == name:
                    return _property
        return None

    # 方法的返回值
    def get_return_type_from_method(self, _class, method):
        # 可能是 getter
        if ':' not in method:
            _property = self.get_property_of_class(_class, method)
            if _property is not None:
                return _property._type

        # 查看系统的方法返回值
        if _class in objc_methods_return_type:
            class_methods = objc_methods_return_type[_class]
            if method in class_methods:
                return class_methods[method]
        general_methods = objc_methods_return_type['*']
        if method in general_methods:
            return general_methods[method]

        # 通用的 alloc 或 init 方法
        if method.startswith('alloc') or method.startswith('init'):
            return '$SELF'
        if (_class, method) not in self.methods_type:
            return 'id'
        method_type = self.methods_type[(_class, method)]
        return method_type.return_type

    # 方法的参数列表
    def get_arguments_from_method(self, _class, method):

        if (_class, method) not in self.methods_type:
            if _class in objc_methods_arguments:
                class_methods = objc_methods_arguments[_class]
                if method in class_methods:
                    arguments_type = [ArgumentData('id', 8), ArgumentData('SEL', 8)]
                    for t, l in class_methods[method]:
                        argument_type = ArgumentData(t, l)
                        arguments_type.append(argument_type)
                    return arguments_type
            general_methods = objc_methods_arguments['*']
            if method in general_methods:
                arguments_type = [ArgumentData('id', 8), ArgumentData('SEL', 8)]
                for t, l in general_methods[method]:
                    argument_type = ArgumentData(t, l)
                    arguments_type.append(argument_type)
                return arguments_type
            arguments_type = [ArgumentData('id', 8), ArgumentData('SEL', 8)]
            arguments_count = method.count(':')
            for _ in range(arguments_count):
                arguments_type.append(ArgumentData('id', 8))
            return arguments_type
        method_type = self.methods_type[(_class, method)]
        return method_type.arguments_type

    # 函数的返回值
    def get_return_type_from_function(self, name):
        if name == '___stack_chk_fail':
            return 'None'
        for function_data in self.functions_type:
            if function_data.name == name:
                return function_data.return_type
        if name.startswith('_objc'):
            return 'None'
        return 'None'

    def contain_block_arguments(self, _class, method):
        if _class == '$Function' and method == '_dispatch_once':
            return [1], True
        if _class == '$Function' and method == '_dispatch_after':
            return [2], True
        if _class == 'UIView' and method == 'animateWithDuration:animations:':
            return [2], True  # Duration 在 float 寄存器中
        return [], False

    # 解析 GlobalBlock
    def parse_block(self):

        block_class_names = ['__NSConcreteStackBlock', '__NSConcreteGlobalBlock', '__NSConcreteMallocBlock']
        # print(self.dylibs)
        for dylib_addr in self.dylibs:  # 这个是地址，不是 offset
            dylib_name = self.symbols[hex(self.dylibs[dylib_addr])]
            if dylib_name in block_class_names:
                type = block_class_names.index(dylib_name)
                block_address = int(dylib_addr, 16)
                # print(hex(block_address))
                if self.type == MachObjectTypeExecutable:
                    block_address_start = block_address - (self.offset if not self.is_64_bit else 0x100000000)
                else:
                    block_address_start = block_address
                block_address_end = block_address_start + (ObjcBlock.OB_TOTAL_SIZE if not self.is_64_bit else
                                                           ObjcBlock64.OB_TOTAL_SIZE)

                block_bytes = self.bytes[block_address_start:block_address_end]
                if self.is_64_bit:
                    ob = ObjcBlock64.parse_from_bytes(block_bytes)
                else:
                    ob = ObjcBlock.parse_from_bytes(block_bytes)

                block_data = BlockMethodData(type)
                block_data.invoke = ob.invoke

                self.block_methods[dylib_addr] = block_data
                if hex(block_data.invoke) != '0x0':
                    self.methods[hex(block_data.invoke)] = '$Block', hex(block_data.invoke)
                    if '$Block' not in self.class_methods:
                        self.class_methods['$Block'] = {}
                    self.class_methods['$Block'][hex(block_data.invoke)] = block_data.invoke
                # print(self.methods[hex(block_data.invoke)])

    def parse_cfstring(self):
        cfstring, _ = self._sections["cfstring"]
        base_address = cfstring.addr
        if self.type == MachObjectTypeExecutable:
            cfstring_offset = (cfstring.offset + 0x100000000 if self.is_64_bit else 0) - base_address
        else:
            cfstring_offset = 0

        if self.type == MachObjectTypeExecutable:
            start = base_address - self.offset if not self.is_64_bit else base_address - 0x100000000
        else:
            start = base_address
        start = start + cfstring_offset
        end = start + cfstring.size
        while start < end:
            self.cfstrings[hex(base_address)] = parse_int(self.bytes[start + 16: start + 24])
            base_address += 32
            start += 32

    def parse_dylib_class(self):
        _, dyld_info = self._cmds["dyld_info"][0]
        binding_info_offset = dyld_info.bind_off

        # Binding Info 里面存的是符号的名字以及该名字对应的地址
        # 与 _class_refs 节对应

        pointer = binding_info_offset
        # print(hex(binding_info_offset))
        is_over = False

        lib_ordinal = 0
        # symbol_flags = 0
        symbol_name = None
        # symbol_type = 0
        # symbol_segment = 0
        symbol_key = None
        base_address = 0x0  # 这个应该是 offset
        while not is_over:
            # 这个地方，真的不用减吗
            # 不用减，因为是与当前 Mach-O 开头的 offset
            byte = parse_int(self.bytes[pointer:pointer + 1])
            opcode = byte & BIND_OPCODE_MASK
            if opcode == BIND_OPCODE_DONE:
                # print(byte)
                # print("over: " + hex(pointer + 0x4000))
                is_over = True
            elif opcode == BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
                lib_ordinal = byte & BIND_IMMEDIATE_MASK
            elif opcode == BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
                pointer += 1
                lib_ordinal, length = uleb128(self.bytes, pointer)
                pointer += length
            elif opcode == BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
                immediate = byte & BIND_IMMEDIATE_MASK
                if immediate == 0:
                    lib_ordinal = 0
                else:
                    sign_extended = immediate | BIND_OPCODE_MASK
                    lib_ordinal = sign_extended
            elif opcode == BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
                name_begin = pointer + 1
                name_end = self.bytes.find(b'\x00', name_begin)
                symbol_name = parse_str(self.bytes[name_begin:name_end])
                if self.type == MachObjectTypeExecutable:
                    symbol_key = hex(
                        name_begin + 0x100000000) if self.is_64_bit else hex(name_begin + self.offset)
                else:
                    symbol_key = hex(name_begin)
                self.symbols[symbol_key] = symbol_name
                pointer = name_end
            elif opcode == BIND_OPCODE_SET_TYPE_IMM:
                symbol_type = byte & BIND_IMMEDIATE_MASK
            elif opcode == BIND_OPCODE_SET_ADDEND_SLEB:
                pointer += 1
            elif opcode == BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
                segment_index = byte & BIND_IMMEDIATE_MASK
                symbol_segment = segment_index
                pointer += 1
                val, length = uleb128(self.bytes, pointer)
                if self.is_64_bit:
                    _, segment = self._cmds["segment64"][segment_index]
                else:
                    _, segment = self._cmds["segment"][segment_index]

                # 这个地方被改了
                if self.type == MachObjectTypeExecutable:
                    base_address = (segment.fileoff + (0x100000000 if self.is_64_bit else 0)) + val
                else:
                    base_address = segment.fileoff + val
                pointer += length
            elif opcode == BIND_OPCODE_ADD_ADDR_ULEB:
                pointer += 1
                val, length = uleb128(self.bytes, pointer)
                base_address += val
                pointer += length
            elif opcode == BIND_OPCODE_DO_BIND:
                # print("%d\t%d\t%s\t%d\t%d\t%s" % (lib_ordinal, symbol_flags, symbol_name, symbol_type, symbol_segment, hex(base_address)))
                # print(hex(base_address))
                self.dylib_frameworks_pair[self.symbols[symbol_key]] = self.dylib_frameworks_path[lib_ordinal - 1]

                self.dylibs[hex(base_address)] = int(symbol_key, 16)
                base_address += (8 if self.is_64_bit else 4)
            elif opcode == BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
                pointer += 1
                val, length = uleb128(self.bytes, pointer)
                pointer += length
                # print("%d\t%d\t%s\t%d\t%d\t%s" % (lib_ordinal, symbol_flags, symbol_name, symbol_type, symbol_segment, hex(base_address)))
                self.dylib_frameworks_pair[self.symbols[symbol_key]] = self.dylib_frameworks_path[lib_ordinal - 1]
                self.dylibs[hex(base_address)] = int(symbol_key, 16)
                base_address += ((8 if self.is_64_bit else 4) + val)
            elif opcode == BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
                scale = byte & BIND_IMMEDIATE_MASK
                # print("%d\t%d\t%s\t%d\t%d\t%s" % (lib_ordinal, symbol_flags, symbol_name, symbol_type, symbol_segment, hex(base_address)))
                self.dylib_frameworks_pair[self.symbols[symbol_key]] = self.dylib_frameworks_path[lib_ordinal - 1]
                self.dylibs[hex(base_address)] = int(symbol_key, 16)
                base_address += ((8 if self.is_64_bit else 4) + scale * (8 if self.is_64_bit else 4))
            elif opcode == BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
                pointer += 1
                count, length = uleb128(self.bytes, pointer)
                pointer += length + 1
                skip, length = uleb128(self.bytes, pointer)
                pointer += length
                # print("%d\t%d\t%s\t%d\t%d\t%s" % (lib_ordinal, symbol_flags, symbol_name, symbol_type, symbol_segment, hex(base_address)))
                for _ in range(count):
                    self.dylib_frameworks_pair[self.symbols[symbol_key]] = self.dylib_frameworks_path[lib_ordinal - 1]
                    self.dylibs[hex(base_address)] = int(symbol_key, 16)
                    base_address += (8 if self.is_64_bit else 4) + skip
            pointer += 1

    def parse_cat_methods_and_data(self):
        '''
        Generation:
          > self.methods : {impaddr : (classname, methodname)}
          > self.cat_datas : {cataddr : <cat>}
        '''
        if "objc_catlist" not in self._sections:
            return
        objc_catlist, _ = self._sections["objc_catlist"]
        if self.type == MachObjectTypeExecutable:
            catlist_addr = objc_catlist.addr - self.offset if not self.is_64_bit else objc_catlist.addr - 0x100000000
        else:
            catlist_addr = objc_catlist.addr
        total_size = objc_catlist.size
        each_size = 8 if self.is_64_bit else 4
        count = 0
        while count < int(total_size / each_size):  # 遍历 catlist 中所有类
            catlist_begin = catlist_addr + count * each_size
            cat_bytes = self.bytes[catlist_begin: catlist_begin + each_size]

            if self.type == MachObjectTypeExecutable:
                oc_bytes_begin = (parse_int(cat_bytes) - self.offset if not self.is_64_bit
                                  else parse_int(cat_bytes) - 0x100000000)
            else:
                oc_bytes_begin = parse_int(cat_bytes)
            oc_bytes_end = oc_bytes_begin + (ObjcCategory.OC_TOTAL_SIZE if not self.is_64_bit
                                             else ObjcCategory64.OC_TOTAL_SIZE)
            oc_bytes = self.bytes[oc_bytes_begin:oc_bytes_end]
            if self.is_64_bit:
                objc_category = ObjcCategory64.parse_from_bytes(oc_bytes)
            else:
                objc_category = ObjcCategory.parse_from_bytes(oc_bytes)

            category_name = self.symbols[hex(objc_category.name)]
            cat_data = CatData(category_name)
            if objc_category._class == 0:
                class_name_index = self.dylibs[hex(parse_int(cat_bytes) + (8 if self.is_64_bit else 4))]
                class_name = self.symbols[hex(class_name_index)]
                begin = class_name.find("$") + 2
                class_name = class_name[begin:]
                cat_data._class = class_name

            # instance methods
            if objc_category.instance_methods != 0x0:
                if self.type == MachObjectTypeExecutable:
                    oml_bytes_begin = (objc_category.instance_methods - self.offset if not self.is_64_bit
                                       else objc_category.instance_methods - 0x100000000)
                else:
                    oml_bytes_begin = objc_category.instance_methods
                oml_bytes_end = oml_bytes_begin + (ObjcMethodList.OML_TOTAL_SIZE if not self.is_64_bit
                                                   else ObjcMethodList64.OML_TOTAL_SIZE)
                oml_bytes = self.bytes[oml_bytes_begin:oml_bytes_end]
                if self.is_64_bit:
                    objc_method_list = ObjcMethodList64.parse_from_bytes(oml_bytes)
                else:
                    objc_method_list = ObjcMethodList.parse_from_bytes(oml_bytes)

                for j in range(objc_method_list.method_count):
                    om_bytes_begin = (oml_bytes_begin + objc_method_list.get_size() + j *
                                      (ObjcMethod.OM_TOTAL_SIZE if not self.is_64_bit
                                       else ObjcMethod64.OM_TOTAL_SIZE))
                    om_bytes_end = om_bytes_begin + (ObjcMethod.OM_TOTAL_SIZE if not self.is_64_bit
                                                     else ObjcMethod64.OM_TOTAL_SIZE)
                    om_bytes = self.bytes[om_bytes_begin:om_bytes_end]
                    if self.is_64_bit:
                        objc_method = ObjcMethod64.parse_from_bytes(om_bytes)
                    else:
                        objc_method = ObjcMethod.parse_from_bytes(om_bytes)
                    objc_method_implementation = objc_method.implementation
                    objc_method_name = self.symbols[hex(objc_method.name)]
                    objc_method_signature = self.symbols[hex(
                        objc_method.signature)]
                    return_type, method_args = self.analysis_method_signature(objc_method_signature)
                    method_type = MethodData(cat_data._class, objc_method_name)
                    method_type.return_type = return_type
                    method_type.arguments_type = method_args
                    self.methods_type[(cat_data._class, objc_method_name)] = method_type
                    # if cat_data._class not in self.methods_type:
                    #     self.methods_type[cat_data._class] = []
                    # self.methods_type[cat_data._class].append(method_type)
                    self.methods[hex(objc_method_implementation)] = cat_data._class, objc_method_name
                    if cat_data._class not in self.class_methods:
                        self.class_methods[cat_data._class] = {}
                    self.class_methods[cat_data._class][objc_method_name] = objc_method_implementation

                    cat_data.insert_instance_method(objc_method_name)

            # class methods
            if objc_category.class_methods != 0x0:
                if self.type == MachObjectTypeExecutable:
                    oml_bytes_begin = (objc_category.class_methods - self.offset if not self.is_64_bit
                                       else objc_category.class_methods - 0x100000000)
                else:
                    oml_bytes_begin = objc_category.class_methods
                oml_bytes_end = oml_bytes_begin + (ObjcMethodList.OML_TOTAL_SIZE if not self.is_64_bit
                                                   else ObjcMethodList64.OML_TOTAL_SIZE)
                oml_bytes = self.bytes[oml_bytes_begin:oml_bytes_end]
                if self.is_64_bit:
                    objc_method_list = ObjcMethodList64.parse_from_bytes(oml_bytes)
                else:
                    objc_method_list = ObjcMethodList64.parse_from_bytes(oml_bytes)
                for j in range(objc_method_list.method_count):
                    om_bytes_begin = (oml_bytes_begin + objc_method_list.get_size() + j *
                                      (ObjcMethod.OM_TOTAL_SIZE if not self.is_64_bit
                                       else ObjcMethod64.OM_TOTAL_SIZE))
                    om_bytes_end = om_bytes_begin + (ObjcMethod.OM_TOTAL_SIZE if not self.is_64_bit
                                                     else ObjcMethod64.OM_TOTAL_SIZE)
                    om_bytes = self.bytes[om_bytes_begin:om_bytes_end]
                    if self.is_64_bit:
                        objc_method = ObjcMethod64.parse_from_bytes(om_bytes)
                    else:
                        objc_method = ObjcMethod.parse_from_bytes(om_bytes)
                    objc_method_implementation = objc_method.implementation
                    objc_method_name = self.symbols[hex(objc_method.name)]
                    objc_method_signature = self.symbols[hex(objc_method.signature)]
                    return_type, method_args = self.analysis_method_signature(objc_method_signature)
                    method_type = MethodData(cat_data._class, objc_method_name)
                    method_type.return_type = return_type
                    method_type.arguments_type = method_args
                    # if cat_data._class not in self.methods_type:
                    #     self.methods_type[cat_data._class] = []
                    self.methods_type[(cat_data._class, objc_method_name)] = method_type
                    self.methods[hex(objc_method_implementation)] = (
                        cat_data._class, objc_method_name)
                    if cat_data._class not in self.class_methods:
                        self.class_methods[cat_data._class] = {}
                    self.class_methods[cat_data._class][objc_method_name] = objc_method_implementation
                    cat_data.insert_class_method(objc_method_name)

            # properties
            if objc_category.instance_properties != 0x0:
                if self.type == MachObjectTypeExecutable:
                    opl_bytes_begin = (objc_category.instance_properties - self.offset if not self.is_64_bit
                                       else objc_category.instance_properties - 0x100000000)
                else:
                    opl_bytes_begin = objc_category.instance_properties
                opl_bytes_end = opl_bytes_begin + (ObjcPropertyList.OPL_TOTAL_SIZE if not self.is_64_bit else
                                                   ObjcPropertyList64.OPL_TOTAL_SIZE)
                opl_bytes = self.bytes[opl_bytes_begin:opl_bytes_end]

                if self.is_64_bit:
                    objc_property_list = ObjcPropertyList64.parse_from_bytes(opl_bytes)
                else:
                    objc_property_list = ObjcPropertyList.parse_from_bytes(opl_bytes)

                for j in range(objc_property_list.count):
                    op_bytes_begin = (opl_bytes_begin + objc_property_list.get_size() +
                                      j * (ObjcProperty.OP_TOTAL_SIZE if not self.is_64_bit
                                           else ObjcProperty64.OP_TOTAL_SIZE))
                    op_bytes_end = op_bytes_begin + (ObjcProperty.OP_TOTAL_SIZE if not self.is_64_bit
                                                     else ObjcProperty64.OP_TOTAL_SIZE)
                    op_bytes = self.bytes[op_bytes_begin:op_bytes_end]
                    if self.is_64_bit:
                        objc_property = ObjcProperty64.parse_from_bytes(op_bytes)
                    else:
                        objc_property = ObjcProperty.parse_from_bytes(op_bytes)

                    property_name = self.symbols[hex(objc_property.name)]
                    # print(class_name)
                    # print(property_name)
                    property_attributes = self.symbols[(hex(objc_property.attributes))]
                    if "@" in property_attributes:
                        property_attributes_begin = property_attributes.find(
                            "@\"") + 2
                        property_attributes_end = property_attributes.find(
                            "\"", property_attributes_begin)
                        property_attributes = property_attributes[
                            property_attributes_begin:property_attributes_end]
                    else:
                        property_attributes = ""
                    _property = PropertyData(property_name, property_attributes)
                    cat_data.insert_property(_property)
                # property_key = hex(op_bytes_begin + 0x100000000 if self.is_64_bit else op_bytes_begin)
                # self.properties[hex(property_key)] = _property
                # self.property_refs[]
            self.cat_datas[hex(parse_int(cat_bytes))] = cat_data
            count += 1

    def analysis_method_signature(self, signature):
        # @48@0:8{CGRect={CGPoint=dd}{CGSize=dd}}16
        type_list = []
        position_list = []

        type_encoding = {
            '@': 'id', '#': 'Class', ':': 'SEL',
            'c': 'Char', 'i': 'Integer', 's': 'Integer',
            'l': 'Integer', 'q': 'Integer', 'C': 'Char',
            'I': 'Integer', 'S': 'Integer', 'L': 'Integer',
            'Q': 'Integer', 'f': 'Float', 'd': 'Float',
            'B': 'Bool', 'v': 'None', '*': 'Pointer'
        }

        state_empty = 0
        state_type = 1
        state_position = 2

        state = state_empty
        position_str = ''
        type_str = ''

        i = 0

        bracket_pair = {'{': '}', '[': ']', '(': ')'}
        brackets_stack = []

        while i < len(signature):
            c = signature[i]
            if state == state_empty:
                if c.isdigit():
                    state = state_position
                    position_str += c
                    i += 1
                else:
                    if c in type_encoding:
                        type_list.append(type_encoding[c])
                        i += 1
                    elif c == '{' or c == '[' or c == '(':
                        brackets_stack.append(c)
                        state = state_type
                        i += 1
                    elif c == '^':  # 也是一个指针
                        type_list.append('Pointer')
                        i += 1
                        c = signature[i]
                        if c != '{' and c != '[' and c != '(':
                            while not signature[i].isdigit():
                                i += 1
                        else:
                            brackets_stack.append(c)
                            i += 1
                            while len(brackets_stack) > 0:
                                if signature[i] == bracket_pair[brackets_stack[-1]]:
                                    brackets_stack = brackets_stack[:-1]
                                if signature[i] in bracket_pair:
                                    brackets_stack.append(signature[i])
                                i += 1
                    else:
                        i += 1
            elif state == state_position:
                if c.isdigit():
                    position_str += c
                    i += 1
                else:
                    state = state_empty
                    position_list.append(int(position_str))
                    position_str = ''
            elif state == state_type:
                if c.isalnum() or c == '_':
                    type_str += c
                    i += 1
                else:
                    type_list.append(type_str)
                    type_str = ''

                    while len(brackets_stack) > 0:
                        if signature[i] == bracket_pair[brackets_stack[-1]]:
                            brackets_stack = brackets_stack[:-1]
                        if signature[i] in bracket_pair:
                            brackets_stack.append(signature[i])
                        i += 1

                    # while not signature[i].isdigit():
                    #     i += 1
                    state = state_empty

        if state == state_position:
            position_list.append(int(position_str))

        tmp = type_list[0]
        type_list = type_list[1:]
        type_list.append(tmp)
        tmp = position_list[0]
        position_list = position_list[1:]
        position_list.append(tmp)

        return_type = type_list[-1]
        arguments = []
        if len(type_list) == 0:
            return 'id', []
        for i in range(len(type_list) - 1):
            arg_type = type_list[i]
            length = position_list[i + 1] - position_list[i]
            argument = ArgumentData(arg_type, length)
            arguments.append(argument)
        return return_type, arguments

    def get_class_data(self, _bytes):
        '''
        Get class structure and class_data structure from _bytes indicate
        :param _bytes: the class structure's address
        :return: (class, class_data)
        '''
        if self.type == MachObjectTypeExecutable:
            oc_bytes_begin = (parse_int(_bytes) - self.offset if not self.is_64_bit
                              else parse_int(_bytes) - 0x100000000)
        else:
            oc_bytes_begin = parse_int(_bytes)
        oc_bytes_end = oc_bytes_begin + (ObjcClass.OC_TOTAL_SIZE if not self.is_64_bit
                                         else ObjcClass64.OC_TOTAL_SIZE)
        oc_bytes = self.bytes[oc_bytes_begin:oc_bytes_end]
        if self.is_64_bit:
            objc_class = ObjcClass64.parse_from_bytes(oc_bytes)
        else:
            objc_class = ObjcClass.parse_from_bytes(oc_bytes)

        if self.type == MachObjectTypeExecutable:
            od_bytes_begin = (objc_class.data - self.offset if not self.is_64_bit
                              else objc_class.data - 0x100000000)
        else:
            od_bytes_begin = objc_class.data
        od_bytes_end = od_bytes_begin + (ObjcData.OD_TOTAL_SIZE if not self.is_64_bit
                                         else ObjcData64.OD_TOTAL_SIZE)
        od_bytes = self.bytes[od_bytes_begin:od_bytes_end]
        if self.is_64_bit:
            objc_data = ObjcData64.parse_from_bytes(od_bytes)
        else:
            objc_data = ObjcData.parse_from_bytes(od_bytes)
        return objc_class, objc_data

    def parse_class_methods_and_data(self):
        # TO-DO: 添加 class_data 中的 properties
        '''
        Generation:
          > self.methods : {impaddr : (classname, methodname)}
          > self.ivar_refs : {<> : index}
          > self.ivars : {refindex : <ivar>}
          > self.class_datas : {classaddr : <class>}
        '''
        objc_classlist, _ = self._sections["objc_classlist"]
        if self.type == MachObjectTypeExecutable:
            classlist_addr = (
                objc_classlist.addr - self.offset if not self.is_64_bit else objc_classlist.addr - 0x100000000)
        else:
            classlist_addr = objc_classlist.addr
        total_size = objc_classlist.size
        each_size = 8 if self.is_64_bit else 4
        count = 0
        while count < int(total_size / each_size):  # 遍历 classlist 中的所有类
            classlist_begin = classlist_addr + count * each_size
            class_bytes = self.bytes[classlist_begin:classlist_begin + each_size]

            # 当前类的数据
            objc_class, objc_data = self.get_class_data(class_bytes)
            # 元类的数据
            meta_class_bytes = objc_class.metaclass.to_bytes(8 if self.is_64_bit else 4, 'little')
            meta_objc_class, meta_objc_data = self.get_class_data(meta_class_bytes)

            class_name = self.symbols[hex(objc_data.name)]
            class_data = ClassData(class_name)

            # 解析实例方法
            if objc_data.base_methods != 0x0:  # not contain any method
                if self.type == MachObjectTypeExecutable:
                    oml_bytes_begin = (objc_data.base_methods - self.offset if not self.is_64_bit
                                       else objc_data.base_methods - 0x100000000)
                else:
                    oml_bytes_begin = objc_data.base_methods
                oml_bytes_end = oml_bytes_begin + (ObjcMethodList.OML_TOTAL_SIZE if not self.is_64_bit
                                               else ObjcMethodList64.OML_TOTAL_SIZE)
                oml_bytes = self.bytes[oml_bytes_begin:oml_bytes_end]
                if self.is_64_bit:
                    objc_method_list = ObjcMethodList64.parse_from_bytes(oml_bytes)
                else:
                    objc_method_list = ObjcMethodList.parse_from_bytes(oml_bytes)

                for j in range(objc_method_list.method_count):
                    om_bytes_begin = (oml_bytes_begin + objc_method_list.get_size() + j *
                                     (ObjcMethod.OM_TOTAL_SIZE if not self.is_64_bit
                                      else ObjcMethod64.OM_TOTAL_SIZE))
                    om_bytes_end = om_bytes_begin + (ObjcMethod.OM_TOTAL_SIZE if not self.is_64_bit
                                                     else ObjcMethod64.OM_TOTAL_SIZE)
                    om_bytes = self.bytes[om_bytes_begin:om_bytes_end]
                    if self.is_64_bit:
                        objc_method = ObjcMethod64.parse_from_bytes(om_bytes)
                    else:
                        objc_method = ObjcMethod.parse_from_bytes(om_bytes)
                    objc_method_implementation = objc_method.implementation

                    objc_method_name = self.symbols[hex(objc_method.name)]

                    objc_method_signature = self.symbols[hex(objc_method.signature)]
                    # 获得方法返回值和参数
                    return_type, method_args = self.analysis_method_signature(objc_method_signature)
                    method_type = MethodData(class_name, objc_method_name)
                    method_type.return_type = return_type
                    method_type.arguments_type = method_args
                    # if class_name not in self.methods_type:
                    #     self.methods_type[class_name] = []
                    self.methods_type[(class_name, objc_method_name)] = method_type
                    self.methods[hex(objc_method_implementation)] = (
                        class_name, objc_method_name)
                    if class_name not in self.class_methods:
                        self.class_methods[class_name] = {}
                    self.class_methods[class_name][objc_method_name] = objc_method_implementation
                    class_data.insert_method(objc_method_name)

            # 解析类方法
            if meta_objc_data.base_methods != 0x0:
                if self.type == MachObjectTypeExecutable:
                    oml_bytes_begin = (meta_objc_data.base_methods - self.offset if not self.is_64_bit
                                       else meta_objc_data.base_methods - 0x100000000)
                else:
                    oml_bytes_begin = meta_objc_data.base_methods

                oml_bytes_end = oml_bytes_begin + (ObjcMethodList.OML_TOTAL_SIZE if not self.is_64_bit
                                                   else ObjcMethodList64.OML_TOTAL_SIZE)
                oml_bytes = self.bytes[oml_bytes_begin:oml_bytes_end]
                if self.is_64_bit:
                    objc_method_list = ObjcMethodList64.parse_from_bytes(oml_bytes)
                else:
                    objc_method_list = ObjcMethodList.parse_from_bytes(oml_bytes)

                for j in range(objc_method_list.method_count):
                    om_bytes_begin = (oml_bytes_begin + objc_method_list.get_size() + j *
                                      (ObjcMethod.OM_TOTAL_SIZE if not self.is_64_bit
                                       else ObjcMethod64.OM_TOTAL_SIZE))
                    om_bytes_end = om_bytes_begin + (ObjcMethod.OM_TOTAL_SIZE if not self.is_64_bit
                                                     else ObjcMethod64.OM_TOTAL_SIZE)
                    om_bytes = self.bytes[om_bytes_begin:om_bytes_end]
                    if self.is_64_bit:
                        objc_method = ObjcMethod64.parse_from_bytes(om_bytes)
                    else:
                        objc_method = ObjcMethod.parse_from_bytes(om_bytes)
                    objc_method_implementation = objc_method.implementation
                    objc_method_name = self.symbols[hex(objc_method.name)]
                    objc_method_signature = self.symbols[hex(objc_method.signature)]
                    return_type, method_args = self.analysis_method_signature(objc_method_signature)
                    method_type = MethodData(class_name, objc_method_name, MethodDataTypeClass)
                    method_type.return_type = return_type
                    method_type.arguments_type = method_args
                    # if class_name not in self.methods_type:
                    #     self.methods_type[class_name] = []
                    self.methods_type[(class_name, objc_method_name)] = method_type
                    self.methods[hex(objc_method_implementation)] = (class_name, objc_method_name)
                    if class_name not in self.class_methods:
                        self.class_methods[class_name] = {}
                    self.class_methods[class_name][objc_method_name] = objc_method_implementation
                    class_data.insert_method(objc_method_name)

            # 解析 ivars
            if objc_data.ivar != 0:
                if self.type == MachObjectTypeExecutable:
                    oil_bytes_begin = (objc_data.ivar - self.offset if not self.is_64_bit
                                       else objc_data.ivar - 0x100000000)
                else:
                    oil_bytes_begin = objc_data.ivar
                oil_bytes_end = oil_bytes_begin + (ObjcIvar.OI_TOTAL_SIZE if not self.is_64_bit
                                                   else ObjcIvar64.OI_TOTAL_SIZE)
                oil_bytes = self.bytes[oil_bytes_begin:oil_bytes_end]
                if self.is_64_bit:
                    objc_ivars = ObjcIvars64.parse_from_bytes(oil_bytes)
                else:
                    objc_ivars = ObjcIvars.parse_from_bytes(oil_bytes)
                for j in range(objc_ivars.count):
                    oi_bytes_begin = (oil_bytes_begin + objc_ivars.get_size() + j *
                                      (ObjcIvar.OI_TOTAL_SIZE if not self.is_64_bit
                                       else ObjcIvar64.OI_TOTAL_SIZE))
                    oi_bytes_end = oi_bytes_begin + (ObjcIvar.OI_TOTAL_SIZE if not self.is_64_bit
                                                     else ObjcIvar64.OI_TOTAL_SIZE)
                    oi_bytes = self.bytes[oi_bytes_begin:oi_bytes_end]
                    if self.is_64_bit:
                        objc_ivar = ObjcIvar64.parse_from_bytes(oi_bytes)
                    else:
                        objc_ivar = ObjcIvar.parse_from_bytes(oi_bytes)
                    objc_ivar_name = self.symbols[hex(objc_ivar.name)]
                    objc_ivar_type = self.symbols[hex(objc_ivar.type)]
                    if "@" in objc_ivar_type:
                        objc_ivar_type_begin = objc_ivar_type.find("@\"") + 2
                        objc_ivar_type_end = objc_ivar_type.find(
                            "\"", objc_ivar_type_begin)
                        objc_ivar_type = objc_ivar_type[objc_ivar_type_begin:objc_ivar_type_end]
                    else:
                        objc_ivar_type = ""
                    ivar = IvarData(objc_ivar_name, objc_ivar_type)
                    class_data.insert_ivar(ivar)

                    ivar_offset_pointer = objc_ivar.offset_pointer
                    if self.type == MachObjectTypeExecutable:
                        ivar_offset_begin = ivar_offset_pointer - self.offset if not self.is_64_bit else ivar_offset_pointer - 0x100000000
                    else:
                        ivar_offset_begin = ivar_offset_pointer
                    # print('ivar_offset_begin: ' + hex(ivar_offset_begin))
                    ivar_offset = parse_int(
                        self.bytes[ivar_offset_begin:ivar_offset_begin + (8 if self.is_64_bit else 4)])
                    self.ivars[hex(ivar_offset_pointer)] = ivar_offset
                    # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
                    # ivar 有问题  !!!!!!!!!!!!!!!!!!!!!!!!!!
                    # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
                    # print('ivar_offset: ' + hex(ivar_offset))
                    self.ivar_refs[hex(ivar_offset)] = len(
                        class_data.ivars) - 1

            # 解析 property
            if objc_data.base_properties > 0:
                if self.type == MachObjectTypeExecutable:
                    opl_bytes_begin = (objc_data.base_properties - self.offset if not self.is_64_bit
                                       else objc_data.base_properties - 0x100000000)
                else:
                    opl_bytes_begin = objc_data.base_properties
                opl_bytes_end = opl_bytes_begin + (ObjcPropertyList.OPL_TOTAL_SIZE if not self.is_64_bit
                                                   else ObjcPropertyList64.OPL_TOTAL_SIZE)
                opl_bytes = self.bytes[opl_bytes_begin:opl_bytes_end]
                if self.is_64_bit:
                    # print(hex(opl_bytes_begin))
                    opl = ObjcPropertyList64.parse_from_bytes(opl_bytes)
                else:
                    opl = ObjcPropertyList.parse_from_bytes(opl_bytes)
                for j in range(opl.count):
                    op_bytes_begin = (opl_bytes_begin + opl.get_size() + j *
                                      (ObjcProperty.OP_TOTAL_SIZE if not self.is_64_bit
                                       else ObjcProperty64.OP_TOTAL_SIZE))
                    op_bytes_end = op_bytes_begin + (ObjcProperty.OP_TOTAL_SIZE if not self.is_64_bit
                                                     else ObjcProperty64.OP_TOTAL_SIZE)
                    op_bytes = self.bytes[op_bytes_begin:op_bytes_end]
                    if self.is_64_bit:
                        op = ObjcProperty64.parse_from_bytes(op_bytes)
                    else:
                        op = ObjcProperty.parse_from_bytes(op_bytes)

                    property_name = self.symbols[hex(op.name)]
                    property_type = self.symbols[hex(op.attributes)]
                    p_t_c = property_type[1]
                    if p_t_c == '@':
                        index = property_type.find('\"', 3)
                        property_type = property_type[3:index]
                    else:
                        type_encoding = {
                            '@': 'id', '#': 'Class', ':': 'SEL',
                            'c': 'Char', 'i': 'Integer', 's': 'Integer',
                            'l': 'Integer', 'q': 'Integer', 'C': 'Char',
                            'I': 'Integer', 'S': 'Integer', 'L': 'Integer',
                            'Q': 'Integer', 'f': 'Float', 'd': 'Float',
                            'B': 'Bool', 'v': 'None', '*': 'Pointer'
                        }
                        if p_t_c in type_encoding:
                            property_type = type_encoding[p_t_c]
                    _property = PropertyData(property_name, property_type)
                    class_data.insert_property(_property)

            # 解析超类
            if self.type == MachObjectTypeExecutable:
                super_class_addr = (objc_class.superclass - self.offset if not self.is_64_bit
                                    else objc_class.superclass - 0x100000000)
            else:
                super_class_addr = objc_class.superclass
            if super_class_addr <= 0:
                # print(class_name + ": " + hex(parse_int(class_bytes) + 8))
                super_key = hex(parse_int(class_bytes) + (8 if self.is_64_bit else 4))
                if super_key in self.dylibs:
                    _super = self.dylibs[hex(parse_int(class_bytes) + (8 if self.is_64_bit else 4))]
                    super_name = self.symbols[hex(_super)]
                    begin = super_name.find("$") + 2
                    super_name = super_name[begin:]
                    class_data.super = super_name
                else:
                    class_data.super = "$Unknown"
            else:
                super_class_bytes = self.bytes[super_class_addr:
                                               super_class_addr + (ObjcClass.OC_TOTAL_SIZE if not self.is_64_bit
                                                                   else ObjcClass64.OC_TOTAL_SIZE)]
                if self.is_64_bit:
                    super_class = ObjcClass64.parse_from_bytes(super_class_bytes)
                else:
                    super_class = ObjcClass.parse_from_bytes(super_class_bytes)

                if self.type == MachObjectTypeExecutable:
                    super_data_bytes_begin = (super_class.data - self.offset if not self.is_64_bit
                                              else super_class.data - 0x100000000)
                else:
                    super_data_bytes_begin = super_class.data
                super_data_bytes_end = super_data_bytes_begin + (ObjcData.OD_TOTAL_SIZE if not self.is_64_bit
                                                                 else ObjcData64.OD_TOTAL_SIZE)
                super_data_bytes = self.bytes[super_data_bytes_begin:super_data_bytes_end]
                if self.is_64_bit:
                    super_data = ObjcData64.parse_from_bytes(super_data_bytes)
                else:
                    super_data = ObjcData.parse_from_bytes(super_data_bytes)
                super_name = self.symbols[hex(super_data.name)]
                class_data.super = super_name
            self.class_name_address[class_name] = parse_int(class_bytes)
            self.class_datas[hex(parse_int(class_bytes))] = class_data
            count += 1

    def parse_methtype(self):
        methtype, _ = self._sections["objc_methtype"]
        base_addr = methtype.addr

        if self.type == MachObjectTypeExecutable:
            methtype_offset = (methtype.offset + (0x100000000 if self.is_64_bit else 0)) - methtype.addr
        else:
            methtype_offset = 0
        # print(hex(base_addr))
        if self.type == MachObjectTypeExecutable:
            begin_pointer = base_addr - self.offset if not self.is_64_bit else base_addr - 0x100000000
        else:
            begin_pointer = base_addr

        begin_pointer = begin_pointer + methtype_offset
        end_pointer = begin_pointer + methtype.size
        while begin_pointer < end_pointer:
            name_begin = begin_pointer

            methtype_key = hex(base_addr)
            if self.bytes[name_begin:name_begin + 1] == b'\x00':
                self.symbols[methtype_key] = ''
                base_addr += 1
                begin_pointer += 1
            else:
                name_end = self.bytes.find(b'\x00', name_begin + 1)
                name_bytes = self.bytes[name_begin:name_end]
                # print(methtype_key)
                self.symbols[methtype_key] = parse_str(name_bytes)
                # print(hex(name_begin + 0x100000000), name_bytes.hex())

                base_addr += (name_end - name_begin + 1)
                begin_pointer = name_end + 1

    def parse_cstring(self):
        cstring, _ = self._sections["cstring"]
        base_addr = cstring.addr

        if self.type == MachObjectTypeExecutable:
            cstring_offset = (cstring.offset + 0x100000000 if self.is_64_bit else 0) - base_addr
        else:
            cstring_offset = 0

        if self.type == MachObjectTypeExecutable:
            begin_pointer = base_addr - self.offset if not self.is_64_bit else base_addr - 0x100000000
        else:
            begin_pointer = base_addr

        begin_pointer += cstring_offset
        end_pointer = begin_pointer + cstring.size
        while begin_pointer < end_pointer:
            name_begin = begin_pointer

            cstring_key = hex(base_addr)
            if self.bytes[name_begin:name_begin + 1] == b'\x00':
                self.symbols[cstring_key] = ''
                base_addr += 1
                begin_pointer += 1
            else:
                name_end = self.bytes.find(b'\x00', name_begin + 1)
                name_bytes = self.bytes[name_begin:name_end]
                self.symbols[cstring_key] = parse_str(name_bytes)
                base_addr += (name_end - name_begin + 1)
                begin_pointer = name_end + 1

    def parse_classname(self):
        objc_classname, _ = self._sections["objc_classname"]
        base_addr = objc_classname.addr
        if self.type == MachObjectTypeExecutable:
            classname_offset = (objc_classname.offset + 0x100000000 if self.is_64_bit else 0) - base_addr
        else:
            classname_offset = 0
        if self.type == MachObjectTypeExecutable:
            begin_pointer = base_addr - self.offset if not self.is_64_bit else base_addr - 0x100000000
        else:
            begin_pointer = base_addr
        begin_pointer += classname_offset
        end_pointer = begin_pointer + objc_classname.size
        while begin_pointer < end_pointer:
            class_name_key = hex(base_addr)
            name_begin = begin_pointer
            if self.bytes[name_begin:name_begin + 1] == b'\x00':
                self.symbols[class_name_key] = ''
                base_addr += 1
                begin_pointer += 1
            else:
                name_end = self.bytes.find(b'\x00', name_begin + 1)
                name_bytes = self.bytes[name_begin:name_end]
                self.symbols[class_name_key] = parse_str(name_bytes)
                base_addr += (name_end - name_begin + 1)
                begin_pointer = name_end + 1

    def parse_methname(self):
        objc_methname, _ = self._sections["objc_methname"]

        base_addr = objc_methname.addr
        if self.type == MachObjectTypeExecutable:
            methname_offset = (objc_methname.offset + 0x100000000 if self.is_64_bit else 0) - base_addr
        else:
            methname_offset = 0

        if self.type == MachObjectTypeExecutable:
            begin_pointer = base_addr - self.offset if not self.is_64_bit else base_addr - 0x100000000
        else:
            begin_pointer = base_addr

        begin_pointer += methname_offset
        end_pointer = begin_pointer + objc_methname.size

        while begin_pointer < end_pointer:
            name_begin = begin_pointer

            method_name_key = hex(base_addr)
            if self.bytes[name_begin:name_begin + 1] == b'\x00':
                self.symbols[method_name_key] = ''
                base_addr += 1
                begin_pointer += 1
            else:
                name_end = self.bytes.find(b'\x00', name_begin + 1)
                name_bytes = self.bytes[name_begin:name_end]
                self.symbols[method_name_key] = parse_str(name_bytes)
                base_addr += (name_end - name_begin + 1)
                begin_pointer = name_end + 1

    def parse_functions(self):
        _, dysymtab = self._cmds["dysymtab"][0]
        _, symtab = self._cmds["symtab"][0]
        picsymbolstub4, _ = self._sections["picsymbolstub4"]
        _, text_index = self._sections["text"]

        symoff = symtab.symoff
        nlist_size = Nlist.N_TOTAL_SIZE

        indirectsymoff = dysymtab.indirectsymoff  # 获得动态符号表偏移
        offset = picsymbolstub4.reserved1
        total_size = picsymbolstub4.size
        each_size = picsymbolstub4.reserved2
        count = 0
        while count < int(total_size / each_size):
            index_begin = indirectsymoff + (count + offset) * 4
            index_bytes = self.bytes[index_begin:index_begin + 4]
            index = parse_int(index_bytes)

            nlist_begin = symoff + index * nlist_size
            nlist_bytes = self.bytes[nlist_begin:nlist_begin + nlist_size]
            nlist = Nlist.parse_from_bytes(nlist_bytes)
            stubs_key = hex(picsymbolstub4.addr + count * each_size)

            symbol_addr = symtab.stroff + nlist.n_strx
            if self.type == MachObjectTypeExecutable:
                symbol_addr += self.offset
            self.functions[stubs_key] = symbol_addr
            count += 1

        sym_num = symtab.nsyms
        count = 0
        while count < sym_num:
            nlist_begin = symoff + count * nlist_size
            nlist_bytes = self.bytes[nlist_begin:nlist_begin + nlist_size]
            nlist = Nlist.parse_from_bytes(nlist_bytes)
            if nlist.n_sect == text_index:
                key = hex(nlist.n_value)
                symbol_addr = symtab.stroff + nlist.n_strx
                if self.type == MachObjectTypeExecutable:
                    symbol_addr += self.offset

                minimum_address = self.text_addr
                if self.type != MachObjectTypeExecutable:
                    minimum_address -= self.offset
                if int(key, 16) >= minimum_address:

                    self.functions[key] = symbol_addr
                # self.functions[key] = symbol_addr

            count += 1

    def parse_functions64(self):
        _, dysymtab = self._cmds["dysymtab"][0]
        _, symtab = self._cmds["symtab"][0]
        stubs, _ = self._sections["stubs"]
        _, text_index = self._sections["text"]

        symoff = symtab.symoff
        nlist_size = Nlist64.N_TOTAL_SIZE

        indirectsymoff = dysymtab.indirectsymoff
        offset = stubs.reserved1
        total_size = stubs.size
        each_size = stubs.reserved2
        count = 0
        # stubs 函数
        while count < int(total_size / each_size):
            # 感觉这个 offset 是不是加错了啊
            index_begin = indirectsymoff + (count + offset) * 4  # indirect symbol table 里存的是索引
            index_bytes = self.bytes[index_begin:index_begin + 4]
            index = parse_int(index_bytes)  # 从 indirect symbol table 里获得索引之后，去 symbol table 里去取

            nlist_begin = symoff + index * nlist_size  # symbol table 里存的表项
            nlist_bytes = self.bytes[nlist_begin:nlist_begin + nlist_size]
            nlist = Nlist64.parse_from_bytes(nlist_bytes)
            stubs_key = hex(stubs.addr + count * each_size)
            # self.function_names[stubs_key] = self.symbols[hex(
            # symtab.stroff + nlist.n_strx)]
            symbol_addr = symtab.stroff + nlist.n_strx  # nlist 里面存有该（函数）名字的符号在符号表里的索引
            if self.type == MachObjectTypeExecutable:
                symbol_addr += 0x100000000
            if nlist.n_desc & 0x00ff == 0:
                dylib_index = (nlist.n_desc & 0xff00) >> 8
                # 函数与其对应的动态库
                # print(self.symbols[hex(symbol_addr)], self.dylib_frameworks_path[dylib_index - 1])
            self.functions[stubs_key] = symbol_addr
            count += 1

        sym_num = symtab.nsyms
        count = 0
        while count < sym_num:
            nlist_begin = symoff + count * nlist_size
            nlist_bytes = self.bytes[nlist_begin:nlist_begin + nlist_size]
            nlist = Nlist64.parse_from_bytes(nlist_bytes)
            if nlist.n_type == 0x0e and nlist.n_sect == text_index:
                key = hex(nlist.n_value)
                # self.function_names[key] = self.symbols[hex(
                # symtab.stroff + nlist.n_strx)]
                symbol_addr = symtab.stroff + nlist.n_strx
                if self.type == MachObjectTypeExecutable:
                    symbol_addr += 0x100000000

                minimum_address = self.text_addr
                if self.type != MachObjectTypeExecutable:
                    minimum_address -= 0x100000000
                if int(key, 16) >= minimum_address:
                    self.functions[key] = symbol_addr
            count += 1

    def parse_symtab(self):
        _, symtab = self._cmds["symtab"][0]

        if "bss" in self._sections:
            _, bss_index = self._sections["bss"]  # bss 段一般存放 static 变量
        else:
            bss_index = -1
        _, text_index = self._sections["text"]

        begin_pointer = symtab.symoff
        nlist_size = Nlist.N_TOTAL_SIZE if not self.is_64_bit else Nlist64.N_TOTAL_SIZE
        for _ in range(symtab.nsyms):

            nlist_bytes = self.bytes[begin_pointer:begin_pointer + nlist_size]
            if self.is_64_bit:
                nlist = Nlist64.parse_from_bytes(nlist_bytes)
            else:
                nlist = Nlist.parse_from_bytes(nlist_bytes)

            name_begin = nlist.n_strx + symtab.stroff
            name_end = self.bytes.find(b'\x00', name_begin + 1)
            name_bytes = self.bytes[name_begin:name_end]
            name = parse_str(name_bytes)
            if self.type == MachObjectTypeExecutable:
                symbol_addr = name_begin + 0x100000000 if self.is_64_bit else name_begin + self.offset
            else:
                symbol_addr = name_begin
            symbol_key = hex(symbol_addr)
            self.symbols[symbol_key] = name
            begin_pointer += nlist.get_size()

            if nlist.n_sect == bss_index:  # 位于 bss 段中的常量
                key = hex(nlist.n_value)
                self.statics[key] = symbol_addr

            if nlist.n_sect == text_index:
                imp_addr = hex(nlist.n_value)
                # print(imp_addr)
                # key = hex(nlist.n_value)
                # symbol_addr = symtab.stroff + nlist.n_strx
                # if self.is_64_bit:
                #     symbol_addr += 0x100000000
                # else:
                #     symbol_addr += self.offset
                # self.statics[key] = symbol_addr

    def aple_header(self):
        header_size = (MachHeader64.MH_TOTAL_SIZE if self.is_64_bit
                       else MachHeader.MH_TOTAL_SIZE)
        header_bytes = self.bytes[0:header_size]
        if self.is_64_bit:
            return MachHeader64.parse_from_bytes(header_bytes)
        else:
            return MachHeader.parse_from_bytes(header_bytes)

    # get apple loaders
    def aple_cmds(self):
        cmds = {}
        header = self.aple_header()
        lc_pointer = header.get_size()
        for _ in range(self.ncmds):
            cmd_bytes = self.bytes[lc_pointer:lc_pointer +
                                   LoadCommand.LC_TOTAL_SIZE]
            cmd = LoadCommand.parse_from_bytes(cmd_bytes)

            if cmd.cmd == LoadCommand.LC_SYMTAB:
                cmd = self.aple_symtab_cmd(lc_pointer)
                self.insert_cmd("symtab", lc_pointer, cmd, cmds)
            elif cmd.cmd == LoadCommand.LC_DYSYMTAB:
                cmd = self.aple_dysymtab_cmd(lc_pointer)
                self.insert_cmd("dysymtab", lc_pointer, cmd, cmds)
            elif cmd.cmd == LoadCommand.LC_SEGMENT:
                cmd = self.aple_segment_cmd(lc_pointer)
                self.insert_cmd("segment", lc_pointer, cmd, cmds)
            elif cmd.cmd == LoadCommand.LC_SEGMENT_64:
                cmd = self.aple_segment64_cmd(lc_pointer)
                self.insert_cmd("segment64", lc_pointer, cmd, cmds)
            elif cmd.cmd == LoadCommand.LC_DYLD_INFO or cmd.cmd == LoadCommand.LC_DYLD_INFO_ONLY:
                cmd = self.apl_dyld_info_cmd(lc_pointer)
                self.insert_cmd("dyld_info", lc_pointer, cmd, cmds)
            elif cmd.cmd == LoadCommand.LC_LOAD_DYLIB or cmd.cmd == LoadCommand.LC_LOAD_WEAK_DYLIB:
                cmd = self.apl_load_dylib_cmd(lc_pointer)
                self.insert_cmd("load_dylib", lc_pointer, cmd, cmds)
            elif cmd.cmd == LoadCommand.LC_RPATH:
                cmd = self.aple_rpath_cmd(lc_pointer)
                self.insert_cmd("load_rpath", lc_pointer, cmd, cmds)

            lc_pointer += cmd.cmdsize
        return cmds

    def aple_rpath_cmd(self, offset=0x0):
        if self.check_aple_cmd(LoadCommand.LC_RPATH, offset):
            cmd_bytes = self.bytes[offset:offset + RpathCommand.RC_TOTAL_SIZE]
            cmd = RpathCommand.parse_from_bytes(cmd_bytes)
            cmd.path = offset + cmd.path
            return cmd
        return None

    def aple_symtab_cmd(self, offset=0x0):
        if self.check_aple_cmd(LoadCommand.LC_SYMTAB, offset):
            cmd_bytes = self.bytes[offset:offset + SymtabCommand.SC_TOTAL_SIZE]
            return SymtabCommand.parse_from_bytes(cmd_bytes)
        return None

    def aple_dysymtab_cmd(self, offset=0x0):
        if self.check_aple_cmd(LoadCommand.LC_DYSYMTAB, offset):
            cmd_bytes = self.bytes[offset:offset +
                                   DysymtabCommand.DC_TOTAL_SIZE]
            return DysymtabCommand.parse_from_bytes(cmd_bytes)
        return None

    def apl_dyld_info_cmd(self, offset=0x0):
        if (self.check_aple_cmd(LoadCommand.LC_DYLD_INFO, offset) or
                self.check_aple_cmd(LoadCommand.LC_DYLD_INFO_ONLY, offset)):
            cmd_bytes = self.bytes[offset:offset +
                                   DyldInfoCommand.DIC_TOTAL_SIZE]
            return DyldInfoCommand.parse_from_bytes(cmd_bytes)
        return None

    def apl_load_dylib_cmd(self, offset=0x0):
        if (self.check_aple_cmd(LoadCommand.LC_LOAD_DYLIB, offset) or
                self.check_aple_cmd(LoadCommand.LC_LOAD_WEAK_DYLIB, offset)):
            cmd_bytes = self.bytes[offset:offset +
                                   LoadDylibCommand.LDC_TOTAL_SIZE]
            cmd = LoadDylibCommand.parse_from_bytes(cmd_bytes)
            cmd.dylib.name = offset + cmd.dylib.name
            return cmd
        return None

    def aple_segment_cmd(self, offset=0x0):
        if self.check_aple_cmd(LoadCommand.LC_SEGMENT, offset):
            cmd_bytes = self.bytes[offset:offset +
                                   SegmentCommand.SC_TOTAL_SIZE]
            return SegmentCommand.parse_from_bytes(cmd_bytes)
        return None

    def aple_segment64_cmd(self, offset=0x0):
        if self.check_aple_cmd(LoadCommand.LC_SEGMENT_64, offset):
            cmd_bytes = self.bytes[offset:offset +
                                   SegmentCommand64.SC_TOTAL_SIZE]
            return SegmentCommand64.parse_from_bytes(cmd_bytes)
        return None

    def check_aple_cmd(self, cmd_type, offset=0x0):
        cmd_bytes = self.bytes[offset:offset + LoadCommand.LC_TOTAL_SIZE]
        cmd = LoadCommand.parse_from_bytes(cmd_bytes)
        if cmd.cmd != cmd_type:
            return False
        return True

    def insert_cmd(self, key, offset, cmd, cmds):
        if key in cmds:
            cmds[key].append((offset, cmd))
        else:
            cmds[key] = []
            cmds[key].append((offset, cmd))

    # get sections
    def aple_sections(self):
        sections = {}
        cmds = self.aple_cmds()
        segments = []
        if self.is_64_bit:
            segments = cmds["segment64"]
        else:
            segments = cmds["segment"]

        total_sect_count = 1
        for offset, segment in segments:

            if (type(segment) != SegmentCommand and
                    type(segment) != SegmentCommand64):
                log_error("Not Segment Command")
            else:
                section_pointer = offset + segment.get_size()
                for _ in range(segment.nsects):
                    section = None
                    if self.is_64_bit:
                        section_bytes = self.bytes[section_pointer:
                                                   section_pointer + Section64.S_TOTAL_SIZE]
                        section = Section64.parse_from_bytes(section_bytes)
                    else:
                        section_bytes = self.bytes[section_pointer:
                                                   section_pointer + Section.S_TOTAL_SIZE]
                        section = Section.parse_from_bytes(section_bytes)

                    section_name = section.sectname
                    print("Found the `%s` section" % (section_name))
                    section_name = section_name[2:]
                    sections[section_name] = (section, total_sect_count)
                    total_sect_count += 1
                    section_pointer += section.get_size()
        return sections

    def convert_to_dict(self):
        mach_object_dict = {
            'type': self.type,  # Number
            'dylib_frameworks_path': self.dylib_frameworks_path,  # list
            'dylib_frameworks_pair': self.dylib_frameworks_pair,  # dict -> str
            'notification_handler': self.notification_handler,  # dict -> str
            'notification_poster': self.notification_poster,  # dict -> str
            'offset': self.offset,  # Number
            'is_64_bit': self.is_64_bit,  # Number
            'cpu_type': self.cpu_type,  # Number
            'cpu_subtype': self.cpu_subtype,  # Number
            'file_type': self.file_type,  # Number
            'ncmds': self.ncmds,  # Number
            'text_addr': self.text_addr,  # Number
            'symbols': self.symbols,  # dict -> str
            'dylibs': self.dylibs,  # dict -> str
            'functions': self.functions,  # dict -> str
            'statics': self.statics,  # dict -> str
            'statics_class': self.statics_class,  # dict -> str

            # 删去 $，因为 key 中不能有 $
            'class_methods': str(self.class_methods),  # dict -> str
            'methods': self.methods,

            'class_name_address': self.class_name_address,
            'cfstrings': self.cfstrings,
            'ivar_refs': self.ivar_refs,
            'ivars': self.ivars,

            'dylib_frameworks_mach': {},
            '_cmds': {},
            '_sections': {},
            'methods_type': {},
            'class_datas': {},
            'cat_datas': {},
            'block_methods': {},

            'bytes': self.bytes,
            'text': self.text
        }

        for path_name in self.dylib_frameworks_mach:
            mach_object_dict['dylib_frameworks_mach'][path_name] = self.dylib_frameworks_mach[path_name].convert_to_dict()

        for key in self._cmds:
            if key not in mach_object_dict['_cmds']:
                mach_object_dict['_cmds'][key] = []
            for offset, cmd in self._cmds[key]:
                mach_object_dict['_cmds'][key].append((offset, cmd.convert_to_dict()))

        for key in self._sections:
            section, index = self._sections[key]
            mach_object_dict['_sections'][key] = (section.convert_to_dict(), index)

        methods_type_dict = {}
        for key in self.methods_type:
            methods_type_dict[key] = self.methods_type[key].convert_to_dict()
        mach_object_dict['methods_type'] = str(methods_type_dict)

        for key in self.class_datas:
            mach_object_dict['class_datas'][key] = self.class_datas[key].convert_to_dict()

        for key in self.cat_datas:
            mach_object_dict['cat_datas'][key] = self.cat_datas[key].convert_to_dict()

        for key in self.block_methods:
            mach_object_dict['block_methods'][key] = self.block_methods[key].convert_to_dict()

        return mach_object_dict
