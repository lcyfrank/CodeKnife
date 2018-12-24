from utils import *

from models.mach_o.fat import *
from models.mach_o.loader import *
from models.mach_o.nlist import *
from models.objc_runtime import *
from models.class_storage import *


class MachContainer:

    def __init__(self, _bytes):
        self.bytes = _bytes
        self.is_fat = _bytes.startswith(b'\xca\xfe\xba\xbe')
        self.mach_objects = []
        self.nfat_arch = 0

        if self.is_fat:
            header = self.aple_header()
            self.nfat_arch = header.nfat_arch
            for i in range(self.nfat_arch):
                arch = self.aple_arch(i)
                mach_bytes = self.bytes[arch.offset:arch.offset + arch.size]
                mach_object = MachObject(mach_bytes)
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
            fat_arch_bytes = self.bytes[header.get_size(
            ) + i * FatArch.FA_TOTAL_SIZE]
            return FatArch.parse_from_bytes(fat_arch_bytes)
        error = ("The index " + str(i) + " is beyond the "
                 "fat architecture's number which is " + str(self.nfat_arch) + ".")
        log_error(error)
        return None


class MachObject:

    def __init__(self, _bytes):
        self.bytes = _bytes
        self.is_64_bit = _bytes.startswith(b'\xcf\xfa\xed\xfe')
        header = self.aple_header()
        self.cpu_type = header.cputype
        self.cpu_subtype = header.cpusubtype
        self.file_type = header.filetype
        self.ncmds = header.ncmds

        self._cmds = self.aple_cmds()
        self._sections = self.aple_sections()

        self.symbols = {}           # address: name
        self.function_names = {}    # impaddr: funcname
        self.method_names = {}      # impaddr: (class, method)
        self.class_datas = {}       # < name, super_name, methods >
        self.dylibs = {}            # address: name

        self.parse_dylib_class()
        self.parse_symtab64()
        self.parse_methname()
        self.parse_functions64()
        self.parse_classname()
        self.parse_class_methods_and_data()

        self.text = self.generate_text()
        self.text_addr = self._sections['text'].addr

    def get_memory_content(self, address, size):
        address = address - 0x100000000
        return self.bytes[address:address + size]

    def generate_text(self):
        text = self._sections['text']
        text_begin = (
            text.addr if not self.is_64_bit else text.addr - 0x100000000)
        text_code = self.bytes[text_begin:text_begin + text.size]
        return text_code

    def parse_dylib_class(self):
        _, dyld_info = self._cmds["dyld_info"][0]
        binding_info_offset = dyld_info.bind_off

        pointer = binding_info_offset
        is_over = False

        lib_ordinal = 0
        # symbol_flags = 0
        # symbol_name = None
        # symbol_type = 0
        # symbol_segment = 0
        base_address = 0x0
        while not is_over:
            byte = parse_int(self.bytes[pointer:pointer + 1])
            opcode = byte & BIND_OPCODE_MASK
            if opcode == BIND_OPCODE_DONE:
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
                pointer = name_end
            elif opcode == BIND_OPCODE_SET_TYPE_IMM:
                symbol_type = byte & BIND_IMMEDIATE_MASK
            elif opcode == BIND_OPCODE_SET_ADDEND_SLEB:
                pass
            elif opcode == BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
                segment_index = byte & BIND_IMMEDIATE_MASK
                symbol_segment = segment_index
                pointer += 1
                val, length = uleb128(self.bytes, pointer)
                _, segment = self._cmds["segment64"][segment_index]
                base_address = segment.vmaddr + val
                pointer += length
            elif opcode == BIND_OPCODE_ADD_ADDR_ULEB:
                pointer += 1
                val, length = uleb128(self.bytes, pointer)
                base_address += val
                pointer += length
            elif opcode == BIND_OPCODE_DO_BIND:
                # print("%d\t%d\t%s\t%d\t%d\t%s" % (lib_ordinal, symbol_flags, symbol_name, symbol_type, symbol_segment, hex(base_address)))
                self.dylibs[hex(base_address)] = symbol_name
                base_address += 8
            elif opcode == BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
                pointer += 1
                val, length = uleb128(self.bytes, pointer)
                pointer += length
                # print("%d\t%d\t%s\t%d\t%d\t%s" % (lib_ordinal, symbol_flags, symbol_name, symbol_type, symbol_segment, hex(base_address)))
                self.dylibs[hex(base_address)] = symbol_name
                base_address += (8 + val)
            elif opcode == BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
                scale = byte & BIND_IMMEDIATE_MASK
                # print("%d\t%d\t%s\t%d\t%d\t%s" % (lib_ordinal, symbol_flags, symbol_name, symbol_type, symbol_segment, hex(base_address)))
                self.dylibs[hex(base_address)] = symbol_name
                base_address += (8 + scale * 8)
            elif opcode == BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
                pointer += 1
                count, length = uleb128(self.bytes, pointer)
                pointer += length + 1
                skip, length = uleb128(self.bytes, pointer)
                pointer += length 
                # print("%d\t%d\t%s\t%d\t%d\t%s" % (lib_ordinal, symbol_flags, symbol_name, symbol_type, symbol_segment, hex(base_address)))
                self.dylibs[hex(base_address)] = symbol_name
                for _ in range(count):
                    base_address += 8 + skip
            pointer += 1
        

    def parse_class_methods_and_data(self):
        objc_classlist = self._sections["objc_classlist"]
        classlist_addr = (
            objc_classlist.addr if not self.is_64_bit else objc_classlist.addr - 0x100000000)
        total_size = objc_classlist.size
        each_size = 8
        count = 0
        while count < int(total_size / each_size):
            classlist_begin = classlist_addr + count * each_size
            class_bytes = self.bytes[classlist_begin:classlist_begin + each_size]
            oc_bytes_begin = (parse_int(class_bytes) if not self.is_64_bit
                              else parse_int(class_bytes) - 0x100000000)
            oc_bytes = self.bytes[oc_bytes_begin:
                                  oc_bytes_begin + ObjcClass64.OC_TOTAL_SIZE]
            objc_class = ObjcClass64.parse_from_bytes(oc_bytes)

            od_bytes_begin = (objc_class.data if not self.is_64_bit
                              else objc_class.data - 0x100000000)
            od_bytes = self.bytes[od_bytes_begin:
                                  od_bytes_begin + ObjcData64.OD_TOTAL_SIZE]
            objc_data = ObjcData64.parse_from_bytes(od_bytes)

            oml_bytes_begin = (objc_data.base_methods if not self.is_64_bit
                               else objc_data.base_methods - 0x100000000)
            oml_bytes = self.bytes[oml_bytes_begin:
                                   oml_bytes_begin + ObjcMethodList64.OML_TOTAL_SIZE]
            objc_method_list = ObjcMethodList64.parse_from_bytes(oml_bytes)

            class_name = self.symbols[hex(objc_data.name)]
            class_data = ClassData(class_name)
            for j in range(objc_method_list.method_count):
                om_bytes_begin = oml_bytes_begin + objc_method_list.get_size() + j * \
                    ObjcMethod64.OM_TOTAL_SIZE
                om_bytes = self.bytes[om_bytes_begin:
                                      om_bytes_begin + ObjcMethod64.OM_TOTAL_SIZE]
                objc_method = ObjcMethod64.parse_from_bytes(om_bytes)
                objc_method_implementation = objc_method.implementation
                objc_method_name = self.symbols[hex(objc_method.name)]
                self.method_names[hex(objc_method_implementation)] = (
                    class_name, objc_method_name)
                class_data.insert_method(objc_method_name)

            super_class_addr = (objc_class.superclass if not self.is_64_bit
                                else objc_class.superclass - 0x100000000)
            if super_class_addr <= 0:
                super_name = self.dylibs[hex(parse_int(class_bytes) + 8)]
                begin = super_name.find("$") + 2
                super_name = super_name[begin:]
                class_data.super = super_name
            else:
                super_class_bytes = self.bytes[super_class_addr:
                                               super_class_addr + ObjcClass64.OC_TOTAL_SIZE]
                super_class = ObjcClass64.parse_from_bytes(super_class_bytes)

                super_data_bytes_begin = (super_class.data if not self.is_64_bit
                                          else super_class.data - 0x100000000)
                super_data_bytes = self.bytes[super_data_bytes_begin:
                                              super_data_bytes_begin + ObjcData64.OD_TOTAL_SIZE]
                super_data = ObjcData64.parse_from_bytes(super_data_bytes)
                super_name = self.symbols[hex(super_data.name)]
                class_data.super = super_name
            self.class_datas[hex(parse_int(class_bytes))] = (class_data)
            count += 1

    def parse_classname(self):
        objc_classname = self._sections["objc_classname"]
        base_addr = objc_classname.addr
        begin_pointer = base_addr if not self.is_64_bit else base_addr - 0x100000000
        end_pointer = begin_pointer + objc_classname.size
        while begin_pointer < end_pointer:
            name_begin = begin_pointer
            name_end = self.bytes.find(b'\x00', name_begin + 1)
            name_bytes = self.bytes[name_begin:name_end]
            class_name_key = hex(base_addr)
            self.symbols[class_name_key] = parse_str(name_bytes)
            base_addr += (name_end - name_begin + 1)
            begin_pointer = name_end + 1

    def parse_methname(self):
        objc_methname = self._sections["objc_methname"]
        base_addr = objc_methname.addr
        begin_pointer = base_addr if not self.is_64_bit else base_addr - 0x100000000
        end_pointer = begin_pointer + objc_methname.size
        while begin_pointer < end_pointer:
            name_begin = begin_pointer
            name_end = self.bytes.find(b'\x00', name_begin + 1)
            name_bytes = self.bytes[name_begin:name_end]
            method_name_key = hex(base_addr)
            self.symbols[method_name_key] = parse_str(name_bytes)
            base_addr += (name_end - name_begin + 1)
            begin_pointer = name_end + 1

    def parse_functions64(self):
        _, dysymtab = self._cmds["dysymtab"][0]
        _, symtab = self._cmds["symtab"][0]
        stubs = self._sections["stubs"]

        symoff = symtab.symoff
        nlist_size = Nlist64.N_TOTAL_SIZE

        indirectsymoff = dysymtab.indirectsymoff
        offset = stubs.reserved1
        total_size = stubs.size
        each_size = stubs.reserved2
        count = 0
        while count < int(total_size / each_size):
            index_begin = indirectsymoff + (count + offset) * 4
            index_bytes = self.bytes[index_begin:index_begin + 4]
            index = parse_int(index_bytes)

            nlist_begin = symoff + index * nlist_size
            nlist_bytes = self.bytes[nlist_begin:nlist_begin + nlist_size]
            nlist = Nlist64.parse_from_bytes(nlist_bytes)
            stubs_key = hex(stubs.addr + count * each_size)
            self.function_names[stubs_key] = self.symbols[hex(
                symtab.stroff + nlist.n_strx)]
            count += 1

        sym_num = symtab.nsyms
        count = 0
        while count < sym_num:
            nlist_begin = symoff + count * nlist_size
            nlist_bytes = self.bytes[nlist_begin:nlist_begin + nlist_size]
            nlist = Nlist64.parse_from_bytes(nlist_bytes)
            if nlist.n_sect == 1:
                key = hex(nlist.n_value)
                self.function_names[key] = self.symbols[hex(symtab.stroff + nlist.n_strx)]
            count += 1

    def parse_symtab64(self):
        _, symtab = self._cmds["symtab"][0]
        begin_pointer = symtab.symoff
        nlist_size = Nlist64.N_TOTAL_SIZE
        for _ in range(symtab.nsyms):
            nlist_bytes = self.bytes[begin_pointer:begin_pointer + nlist_size]
            nlist = Nlist64.parse_from_bytes(nlist_bytes)

            name_begin = nlist.n_strx + symtab.stroff
            name_end = self.bytes.find(b'\x00', name_begin + 1)
            name_bytes = self.bytes[name_begin:name_end]
            name = parse_str(name_bytes)
            self.symbols[hex(name_begin)] = name
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
            elif cmd.cmd == LoadCommand.LC_LOAD_DYLIB:
                cmd = self.apl_load_dylib_cmd(lc_pointer)
                self.insert_cmd("load_dylib", lc_pointer, cmd, cmds)
            lc_pointer += cmd.cmdsize
        return cmds

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
        if self.check_aple_cmd(LoadCommand.LC_LOAD_DYLIB, offset):
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
                    elif section.sectname.startswith('__objc_classname'):
                        print("Found the `__objc_classname` section")
                        sections['objc_classname'] = section
                    elif section.sectname.startswith('__objc_superrefs'):
                        print("Found the `__objc_superrefs` section")
                        sections['objc_superrefs'] = section

                    section_pointer += section.get_size()
        return sections
