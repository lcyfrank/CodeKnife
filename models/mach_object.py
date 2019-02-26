from utils import *

from models.mach_o.fat import *
from models.mach_o.loader import *
from models.mach_o.nlist import *
from models.objc_runtime import *
from models.class_storage import *

SELF_POINTER = -0x1000000
CURRENT_SELECTOR = -0x2000000
RETURN_VALUE = -0x3000000

return_code_with_type = {
    'c': 'char', 'i': 'int', 's': 'short', 'l': 'long', 'q': 'long long', 'c': 'unsigned char',
    'I': 'unsigned int', 'S': 'unsigned short', 'L': 'unsigned long', 'Q': 'unsigned long long',
    'f': 'float', 'd': 'double', 'B': 'BOOL', 'v': 'void', '*': 'char *'
}

class MachContainer:

    def __init__(self, _bytes):
        self.bytes = _bytes
        self.is_fat = _bytes.startswith(b'\xca\xfe\xba\xbe')
        self.mach_objects = []
        self.nfat_arch = 0

        if self.is_fat:
            header = self.aple_header()

            self.nfat_arch = header.nfat_arch
            for i in range(1, self.nfat_arch):  # 现在只调试 64-bit 的 Mach-O 信息
                arch = self.aple_arch(i)
                mach_bytes = self.bytes[arch.offset:arch.offset + arch.size]
                mach_object = MachObject(mach_bytes, arch.offset)
                self.mach_objects.append(mach_object)
        else:
            mach_object = MachObject(_bytes)
            self.mach_objects.append(mach_object)

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


class MachObject:

    def __init__(self, _bytes, _offset=0x0):
        self.bytes = _bytes
        self.offset = _offset
        self.is_64_bit = _bytes.startswith(b'\xcf\xfa\xed\xfe')
        header = self.aple_header()
        self.cpu_type = header.cputype
        self.cpu_subtype = header.cpusubtype
        self.file_type = header.filetype
        self.ncmds = header.ncmds

        self._cmds = self.aple_cmds()
        self._sections = self.aple_sections()

        self.symbols = {}           # address: name
        self.ivar_refs = {}         # <> : index
        # self.property_refs = {}

        self.dylibs = {}            # ref_address: name
        self.functions = {}         # impaddr: symbol_address
        self.functions_type = []    # < function_data >
        self.statics = {}
        self.ivars = {}             # ref_address: <ivar>
        # self.properties = {}

        # self.methods 中的方法均为开发人员实现的方法，包括类中的方法和分类中的方法
        self.methods = {}           # impaddr: (class, method)  / impaddr: (block, block)
        self.methods_type = []      # < method_data >
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

        self.parse_static()       # 修改成兼容 32-bit 和 64-bit

        self.parse_class_methods_and_data()
        self.parse_cat_methods_and_data()
        self.parse_cfstring()

        # print(self.ivar_refs)
        # self.parse_ivars()

        # print(self.statics)
        # print(self.symbols)

        self.text = self.generate_text()
        text_section, _ = self._sections['text']
        self.text_addr = text_section.addr

    def get_method_address(self, class_name, method_name):
        for key in self.methods:
            _class_name, _method_name = self.methods[key]
            if _class_name == class_name and _method_name == method_name:
                return key
        return None

    def get_memory_content(self, address, size):
        address_key = hex(address)
        if address_key in self.dylibs:
            return self.dylibs[address_key]
        elif address_key in self.functions:
            return self.functions[address_key]
        elif address_key in self.ivars:
            return self.ivars[address_key]
        elif address_key in self.statics:
            return self.statics[address_key]
        else:
            if hex(address - SELF_POINTER) in self.ivar_refs:
                return self.ivar_refs[hex(address - SELF_POINTER)]
            else:
                if self.is_64_bit:
                    address = address - 0x100000000
                else:
                    address = address - self.offset  # 因为这个 32-bit 的 address 是相对于整个文件的
                return parse_int(self.bytes[address:address + size])

    def generate_text(self):
        text, _ = self._sections['text']
        text_begin = (
            text.addr - self.offset if not self.is_64_bit else text.addr - 0x100000000)
        text_code = self.bytes[text_begin:text_begin + text.size]
        return text_code

    # 方法的返回值
    def get_return_type_from_method(self, _class, method):

        for method_data in self.methods_type:
            if method_data._class == _class and method_data.name == method:
                return method_data.return_type
        if _class == 'UIScreen' and method == 'mainScreen':
            return 'UIScreen'
        if method == 'view':
            return 'UIView'
        if method.startswith('alloc') or method.startswith('init'):
            return '$SELF'
        # if _class == 'UILabel' and method == 'alloc':
        #     return 'UILabel'
        return 'id'

    # 函数的返回值
    def get_return_type_from_function(self, name):
        for function_data in self.functions_type:
            if function_data.name == name:
                return function_data.return_type
        if name.startswith('_objc'):
            return 'void'
        return 'id'

    # 这个函数等会儿再改
    # def parse_ivars(self):
        # _, symtab = self._cmds["symtab"][0]
        # _, ivar_index = self._sections["objc_ivar"]
        # symoff = symtab.symoff
        # nlist_size = Nlist64.N_TOTAL_SIZE
        # sym_num = symtab.nsyms
        # count = 0
        # while count < sym_num:
        #     nlist_begin = symoff + count * nlist_size
        #     nlist_bytes = self.bytes[nlist_begin:nlist_begin + nlist_size]
        #     nlist = Nlist64.parse_from_bytes(nlist_bytes)
        #     if nlist.n_sect == ivar_index:
        #         key = hex(nlist.n_value)
        #         symbol_key = hex(symtab.stroff + nlist.n_strx + 0x100000000)
        #         name = self.symbols[symbol_key]
        #         class_name_begin = name.find("$") + 2
        #         class_name_end = name.find(".")
        #         class_name = name[class_name_begin:class_name_end]
        #         ivar_name = name[class_name_end + 1:]
        #         ivar = IvarData(ivar_name, class_name)
        #         ivar_ref_addr = nlist.n_value - 0x100000000 if self.is_64_bit else nlist.n_value
        #         ivar_ref = parse_int(
        #             self.bytes[ivar_ref_addr:ivar_ref_addr + 8])
        #         self.ivars[key] = ivar_ref
        #         self.ivar_list.append(ivar)
        #         self.ivar_refs[hex(ivar_ref)] = len(self.ivar_list) - 1
        #     count += 1

    def parse_block(self):

        block_class_names = ['__NSConcreteStackBlock', '__NSConcreteGlobalBlock', '__NSConcreteMallocBlock']
        for dylib_addr in self.dylibs:
            dylib_name = self.symbols[hex(self.dylibs[dylib_addr])]
            if dylib_name in block_class_names:
                type = block_class_names.index(dylib_name)
                block_address = int(dylib_addr, 16)
                block_address_start = block_address - (self.offset if not self.is_64_bit else 0x100000000)
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
                self.methods[hex(block_data.invoke)] = '$Block', dylib_addr
                # print(self.methods[hex(block_data.invoke)])

    def parse_cfstring(self):
        cfstring, _ = self._sections["cfstring"]
        base_address = cfstring.addr

        start = base_address - self.offset if not self.is_64_bit else base_address - 0x100000000
        end = start + cfstring.size
        while start < end:
            self.cfstrings[hex(base_address)] = hex(parse_int(self.bytes[start + 16: start + 24]))
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
        base_address = 0x0
        while not is_over:
            # 这个地方，真的不用减吗
            # 不用减，因为是与当前 Mach-O 开头的 offset
            # print(hex(pointer))
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
                symbol_key = hex(
                    name_begin + 0x100000000) if self.is_64_bit else hex(name_begin + self.offset)
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
                base_address = segment.vmaddr + val
                pointer += length
            elif opcode == BIND_OPCODE_ADD_ADDR_ULEB:
                pointer += 1
                val, length = uleb128(self.bytes, pointer)
                base_address += val
                pointer += length
            elif opcode == BIND_OPCODE_DO_BIND:
                # print("%d\t%d\t%s\t%d\t%d\t%s" % (lib_ordinal, symbol_flags, symbol_name, symbol_type, symbol_segment, hex(base_address)))
                # print(hex(base_address))
                # print(self.symbols[symbol_key])
                self.dylibs[hex(base_address)] = int(symbol_key, 16)
                base_address += (8 if self.is_64_bit else 4)
            elif opcode == BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
                pointer += 1
                val, length = uleb128(self.bytes, pointer)
                pointer += length
                # print("%d\t%d\t%s\t%d\t%d\t%s" % (lib_ordinal, symbol_flags, symbol_name, symbol_type, symbol_segment, hex(base_address)))
                self.dylibs[hex(base_address)] = int(symbol_key, 16)
                base_address += ((8 if self.is_64_bit else 4) + val)
            elif opcode == BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
                scale = byte & BIND_IMMEDIATE_MASK
                # print("%d\t%d\t%s\t%d\t%d\t%s" % (lib_ordinal, symbol_flags, symbol_name, symbol_type, symbol_segment, hex(base_address)))
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
                    self.dylibs[hex(base_address)] = int(symbol_key, 16)
                    base_address += (8 if self.is_64_bit else 4) + skip
            pointer += 1

    def parse_cat_methods_and_data(self):
        '''
        Generation:
          > self.methods : {impaddr : (classname, methodname)}
          > self.cat_datas : {cataddr : <cat>}
        '''
        objc_catlist, _ = self._sections["objc_catlist"]
        catlist_addr = objc_catlist.addr - self.offset if not self.is_64_bit else objc_catlist.addr - 0x100000000
        total_size = objc_catlist.size
        each_size = 8 if self.is_64_bit else 4
        count = 0
        while count < int(total_size / each_size):  # 遍历 catlist 中所有类
            catlist_begin = catlist_addr + count * each_size
            cat_bytes = self.bytes[catlist_begin: catlist_begin + each_size]

            oc_bytes_begin = (parse_int(cat_bytes) - self.offset if not self.is_64_bit
                              else parse_int(cat_bytes) - 0x100000000)
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
                oml_bytes_begin = (objc_category.instance_methods - self.offset if not self.is_64_bit
                                   else objc_category.instance_methods - 0x100000000)
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
                    self.methods_type.append(method_type)
                    self.methods[hex(objc_method_implementation)] = cat_data._class, objc_method_name
                    cat_data.insert_instance_method(objc_method_name)

            # class methods
            if objc_category.class_methods != 0x0:
                oml_bytes_begin = (objc_category.class_methods - self.offset if not self.is_64_bit
                                   else objc_category.class_methods - 0x100000000)
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
                    self.methods_type.append(method_type)
                    self.methods[hex(objc_method_implementation)] = (
                        cat_data._class, objc_method_name)
                    cat_data.insert_class_method(objc_method_name)

            # properties
            if objc_category.instance_properties != 0x0:
                opl_bytes_begin = (objc_category.instance_properties - self.offset if not self.is_64_bit
                                   else objc_category.instance_properties - 0x100000000)
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
        return_type = 'id'
        arguments_type = []
        return_code = signature[0]
        if return_code == '@':  # object
            return_type = 'id'
        elif return_code == '#':  # Class
            return_type = 'Class'
        elif return_code == ':':  # SEL
            return_type = 'SEL'
        elif return_code == '[':  # c-type array
            return_type = 'array'
        elif return_code == '{':  # c-type structure
            return_type = 'structure'
        elif return_code == '(':  # c-type union
            return_type = 'union'
        elif return_code in return_code_with_type:
            return_type = return_code_with_type[return_code]
        else:
            return_type = '?'
        return (return_type, arguments_type)

    def get_class_data(self, _bytes):
        '''
        Get class structure and class_data structure from _bytes indicate
        :param _bytes: the class structure's address
        :return: (class, class_data)
        '''
        oc_bytes_begin = (parse_int(_bytes) - self.offset if not self.is_64_bit
                          else parse_int(_bytes) - 0x100000000)
        oc_bytes_end = oc_bytes_begin + (ObjcClass.OC_TOTAL_SIZE if not self.is_64_bit
                                         else ObjcClass64.OC_TOTAL_SIZE)
        oc_bytes = self.bytes[oc_bytes_begin:oc_bytes_end]
        if self.is_64_bit:
            objc_class = ObjcClass64.parse_from_bytes(oc_bytes)
        else:
            objc_class = ObjcClass.parse_from_bytes(oc_bytes)

        od_bytes_begin = (objc_class.data - self.offset if not self.is_64_bit
                          else objc_class.data - 0x100000000)
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
        classlist_addr = (
            objc_classlist.addr - self.offset if not self.is_64_bit else objc_classlist.addr - 0x100000000)
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
                oml_bytes_begin = (objc_data.base_methods - self.offset if not self.is_64_bit
                                   else objc_data.base_methods - 0x100000000)
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
                    self.methods_type.append(method_type)
                    self.methods[hex(objc_method_implementation)] = (
                        class_name, objc_method_name)
                    class_data.insert_method(objc_method_name)

            # 解析类方法
            if meta_objc_data.base_methods != 0x0:
                oml_bytes_begin = (meta_objc_data.base_methods - self.offset if not self.is_64_bit
                                   else meta_objc_data.base_methods - 0x100000000)

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
                    self.methods_type.append(method_type)
                    self.methods[hex(objc_method_implementation)] = (class_name, objc_method_name)
                    class_data.insert_method(objc_method_name)

            # 解析 ivars
            if objc_data.ivar != 0:
                oil_bytes_begin = (objc_data.ivar - self.offset if not self.is_64_bit
                                   else objc_data.ivar - 0x100000000)
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
                    ivar_offset_begin = ivar_offset_pointer - self.offset if not self.is_64_bit else ivar_offset_pointer - 0x100000000
                    # print('ivar_offset_begin: ' + hex(ivar_offset_begin))
                    ivar_offset = parse_int(
                        self.bytes[ivar_offset_begin:ivar_offset_begin + (8 if self.is_64_bit else 4)])
                    self.ivars[hex(ivar_offset_pointer)] = ivar_offset
                    # print('ivar_offset: ' + hex(ivar_offset))
                    self.ivar_refs[hex(ivar_offset)] = len(
                        class_data.ivars) - 1

            super_class_addr = (objc_class.superclass - self.offset if not self.is_64_bit
                                else objc_class.superclass - 0x100000000)
            if super_class_addr <= 0:
                # print(class_name + ": " + hex(parse_int(class_bytes) + 8))
                _super = self.dylibs[hex(parse_int(class_bytes) + (8 if self.is_64_bit else 4))]
                super_name = self.symbols[hex(_super)]
                begin = super_name.find("$") + 2
                super_name = super_name[begin:]
                class_data.super = super_name
            else:
                super_class_bytes = self.bytes[super_class_addr:
                                               super_class_addr + (ObjcClass.OC_TOTAL_SIZE if not self.is_64_bit
                                                                   else ObjcClass64.OC_TOTAL_SIZE)]
                if self.is_64_bit:
                    super_class = ObjcClass64.parse_from_bytes(super_class_bytes)
                else:
                    super_class = ObjcClass.parse_from_bytes(super_class_bytes)

                super_data_bytes_begin = (super_class.data - self.offset if not self.is_64_bit
                                          else super_class.data - 0x100000000)
                super_data_bytes_end = super_data_bytes_begin + (ObjcData.OD_TOTAL_SIZE if not self.is_64_bit
                                                                 else ObjcData64.OD_TOTAL_SIZE)
                super_data_bytes = self.bytes[super_data_bytes_begin:super_data_bytes_end]
                if self.is_64_bit:
                    super_data = ObjcData64.parse_from_bytes(super_data_bytes)
                else:
                    super_data = ObjcData.parse_from_bytes(super_data_bytes)
                super_name = self.symbols[hex(super_data.name)]
                class_data.super = super_name
            self.class_datas[hex(parse_int(class_bytes))] = (class_data)
            count += 1

    def parse_methtype(self):
        methtype, _ = self._sections["objc_methtype"]
        base_addr = methtype.addr
        begin_pointer = base_addr - self.offset if not self.is_64_bit else base_addr - 0x100000000
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
                self.symbols[methtype_key] = parse_str(name_bytes)
                base_addr += (name_end - name_begin + 1)
                begin_pointer = name_end + 1

    def parse_cstring(self):
        cstring, _ = self._sections["cstring"]
        base_addr = cstring.addr
        begin_pointer = base_addr - self.offset if not self.is_64_bit else base_addr - 0x100000000
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
        begin_pointer = base_addr - self.offset if not self.is_64_bit else base_addr - 0x100000000
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
        begin_pointer = base_addr - self.offset if not self.is_64_bit else base_addr - 0x100000000
        end_pointer = begin_pointer + objc_methname.size
        # print("begin: " + hex(begin_pointer))
        # print("end: " + hex(end_pointer))
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

    def parse_static(self):
        _, symtab = self._cmds["symtab"][0]
        symoff = symtab.symoff
        sym_num = symtab.nsyms
        count = 0
        _, bss_index = self._sections["bss"]  # bss 段一般存放 static 变量

        if self.is_64_bit:
            nlist_size = Nlist64.N_TOTAL_SIZE
        else:
            nlist_size = Nlist.N_TOTAL_SIZE

        while count < sym_num:
            nlist_begin = symoff + count * nlist_size
            nlist_bytes = self.bytes[nlist_begin:nlist_begin + nlist_size]
            if self.is_64_bit:
                nlist = Nlist64.parse_from_bytes(nlist_bytes)
            else:
                nlist = Nlist.parse_from_bytes(nlist_bytes)
            if nlist.n_sect == bss_index:
                key = hex(nlist.n_value)
                symbol_addr = symtab.stroff + nlist.n_strx
                if self.is_64_bit:
                    symbol_addr += 0x100000000
                else:
                    symbol_addr += self.offset
                self.statics[key] = symbol_addr
            count += 1

    def parse_functions(self):
        _, dysymtab = self._cmds["dysymtab"][0]
        _, symtab = self._cmds["symtab"][0]
        picsymbolstub4, _ = self._sections["picsymbolstub4"]
        _, text_index = self._sections["text"]

        symoff = symtab.symoff
        nlist_size = Nlist.N_TOTAL_SIZE

        indirectsymoff = dysymtab.indirectsymoff
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
                symbol_addr += self.offset
                self.functions[key] = symbol_addr
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
        while count < int(total_size / each_size):
            # 感觉这个 offset 是不是加错了啊
            index_begin = indirectsymoff + (count + offset) * 4  # indirect symbol table 里存的是索引
            index_bytes = self.bytes[index_begin:index_begin + 4]
            index = parse_int(index_bytes)  # 从 indirect symbol table 里获得索引之后，去 symbol table 里去取

            nlist_begin = symoff + index * nlist_size
            nlist_bytes = self.bytes[nlist_begin:nlist_begin + nlist_size]
            nlist = Nlist64.parse_from_bytes(nlist_bytes)
            stubs_key = hex(stubs.addr + count * each_size)
            # self.function_names[stubs_key] = self.symbols[hex(
            # symtab.stroff + nlist.n_strx)]
            symbol_addr = symtab.stroff + nlist.n_strx  # nlist 里面存有该（函数）名字的符号在符号表里的索引
            symbol_addr += 0x100000000
            self.functions[stubs_key] = (symbol_addr)
            count += 1

        sym_num = symtab.nsyms
        count = 0
        while count < sym_num:
            nlist_begin = symoff + count * nlist_size
            nlist_bytes = self.bytes[nlist_begin:nlist_begin + nlist_size]
            nlist = Nlist64.parse_from_bytes(nlist_bytes)
            if nlist.n_sect == text_index:
                key = hex(nlist.n_value)
                # self.function_names[key] = self.symbols[hex(
                # symtab.stroff + nlist.n_strx)]
                symbol_addr = symtab.stroff + nlist.n_strx
                symbol_addr += 0x100000000
                self.functions[key] = (symbol_addr)
            count += 1

    def parse_symtab(self):
        _, symtab = self._cmds["symtab"][0]
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
            symbol_key = hex(name_begin + 0x100000000) if self.is_64_bit else hex(name_begin + self.offset)
            self.symbols[symbol_key] = name
            begin_pointer += nlist.get_size()

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
            return RpathCommand.parse_from_bytes(cmd_bytes)
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
            return LoadDylibCommand.parse_from_bytes(cmd_bytes)
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
