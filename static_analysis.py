from models.mach_object import *
from interpreters.inner_Interpreter import *
from models.inner_instruction import *
from cfg_generator import *

# TEST_PATH = './Test'
# TEST_PATH = './Target/HotPatchDemo'
# TEST_PATH = './Target/pinduoduo'
TEST_PATH = './Target/AccountBook'

# Constant
FA_CPU_TYPE_KEY = 'cputype'
FA_CPU_SUBTYPE_KEY = 'cpu_subtype'
FA_OFFSET_KEY = 'offset'
FA_SIZE_KEY = 'size'
FA_ALIGN_KEY = 'align'

_g_return_types = []


def _slice_by_function_for_arm64(model, machine_code, base_addr, slice_addresses):
    functions = []
    current_function = []
    for insn in model.disasm(machine_code, base_addr):
        if hex(insn.address) in slice_addresses:
            if len(current_function) != 0:
                functions.append(current_function)
                current_function = []
            current_function.append(insn)
        else:
            current_function.append(insn)
    return functions    


if __name__ == "__main__":

    mach_o_file = open(TEST_PATH, 'rb')
    mach_container = MachContainer(mach_o_file.read())
    for mach_info in mach_container.mach_objects:
        arch = CS_ARCH_ALL
        mode = CS_MODE_32
        if mach_info.cpu_type == CPU_TYPE_ARM:
            arch = CS_ARCH_ARM
            mode = CS_MODE_THUMB
        elif mach_info.cpu_type == CPU_TYPE_ARM64:
            arch = CS_ARCH_ARM64
            mode = CS_MODE_ARM
        elif mach_info.cpu_type == CPU_TYPE_X86_64:
            arch = CS_ARCH_X86
            mode = CS_MODE_32 if not mach_info.is_64_bit else CS_MODE_64

        model = Cs(arch, mode)
        model.detail = True        

        slice_addresses = list(mach_info.methods.keys())
        slice_addresses += list(mach_info.functions.keys())

        methods = _slice_by_function_for_arm64(model, mach_info.text, mach_info.text_addr, slice_addresses)
        methods_instructions = []
        for method in methods:
            def memory_provider(address):
                try:
                    return mach_info.get_memory_content(address, 8)
                except Exception as _:
                    return 0
            inter = Interpreter(memory_provider)
            if hex(method[0].address) not in mach_info.methods:  # pass the functions
                continue
            class_name, method_name = mach_info.methods[hex(method[0].address)]

            class_data = None
            for data in mach_info.class_datas.values():
                if data.name == class_name:
                    class_data = data
            instruction_block = MethodInstructions(class_name, method_name)
            for i in range(len(method)):
                inter.interpret_code(method, begin=i, end=i+1)
                cs_insn = method[i]
                # if cs_insn.address == 0x100020a68:
                    # print(len(class_data.ivars))
                    # inter.current_state()
                insn_str = hex(cs_insn.address) + '\t' + cs_insn.bytes.hex() + '\t' + cs_insn.mnemonic + '\t' + cs_insn.op_str
                instruction = Instruction(insn_str)
                if cs_insn.id == ARM64_INS_BL or cs_insn.id == ARM64_INS_BLR:
                    operand = cs_insn.operands[0]
                    if operand.type == ARM64_OP_IMM:
                        _function = mach_info.functions[hex(operand.imm)]
                        function_name = mach_info.symbols[hex(_function)]
                        if function_name == "_objc_msgSendSuper2":
                            instruction.goto(class_data.super, method_name)
                        elif function_name == "_objc_msgSend":
                            reg0_value = inter.gen_regs[0].value
                            reg1_value = inter.gen_regs[1].value
                            obj_name = ""
                            if reg0_value == SELF_POINTER:
                                obj_name = class_name
                            elif reg0_value <= RETURN_VALUE:
                                obj_name = _g_return_types[RETURN_VALUE - reg0_value]
                                # if cs_insn.address == 0x10000a60c:
                                #     print(hex(reg0_value))
                            # print(obj_name)
                                # return value
                            elif reg0_value < 0:
                                obj_name = class_data.super
                            else:
                                obj_name_key = hex(reg0_value)
                                if obj_name_key in mach_info.symbols:  # Outter classes
                                    obj_name = mach_info.symbols[obj_name_key]
                                    obj_name_index = obj_name.find('$')
                                    obj_name = obj_name[obj_name_index + 2:]
                                elif obj_name_key in mach_info.class_datas:  # Inner classes
                                    obj_data = mach_info.class_datas[obj_name_key]
                                    obj_name = obj_data.name
                                else:
                                    if class_data != None and hex(reg0_value) in mach_info.ivar_refs:
                                        ivar = class_data.ivars[mach_info.ivar_refs[hex(reg0_value)]]
                                        obj_name = class_name + "->" + ivar.name
                                    elif class_data != None and reg0_value < len(class_data.ivars):  # guess ivars
                                        # print(method_name)
                                        # print('ivars: ' + hex(reg0_value))
                                        ivar = class_data.ivars[reg0_value]
                                        obj_name = class_name + "->" + ivar.name
                                        # print(hex(cs_insn.address))
                                        # print(obj_name)
                                    elif hex(reg0_value) in mach_info.cfstrings:
                                        obj_name = "NSString"
                                    else:  # static vars
                                        # print(hex(cs_insn.address))
                                        # print(hex(reg0_value))
                                        # inter.current_state()
                                        static_name = mach_info.statics[hex(reg0_value)]
                                        obj_name = mach_info.symbols[hex(static_name)]

                            meth_name = mach_info.symbols[hex(reg1_value)]

                            return_type = mach_info.get_return_type_from_method(obj_name, meth_name)
                            # if obj_name == 'UIScreen':
                            #     print(meth_name)
                            #     print(return_type)
                            # 返回值这一块还得处理
                            # if return_type == 'id' or return_type == 'UILabel':  # Now is id
                            if not return_type == 'void':
                                _g_return_types.append(return_type)
                                inter.modify_regs('0', RETURN_VALUE - (len(_g_return_types) - 1))
                            # if cs_insn.address == 0x10000a5f0:
                            #     print(hex(RETURN_VALUE - (len(_g_return_types) - 1)))
                            instruction.goto(obj_name, meth_name)
                        else:
                            instruction.goto("$Function", function_name)
                            return_type = mach_info.get_return_type_from_function(function_name)
                            if not return_type == 'void':
                                _g_return_types.append(return_type)
                                inter.modify_regs('0', RETURN_VALUE - (len(_g_return_types) - 1))
                instruction_block.insert_instruction(instruction)
            # if method_name == 'headerView':
            #     instruction_block.describe()
            # instruction_block.describe()
            MethodStorage.insert_instructions(instruction_block)
            methods_instructions.append(instruction_block)


        def cfg_info_provider(basic_info, imp_name):
            if basic_info == '$Function':
                return None
            else:
                method = MethodStorage.get_instructions(basic_info, imp_name)
                return method
        # MethodStorage.list_all()
        method_instructions = MethodStorage.get_instructions('ABKWelcomeViewController', 'viewDidLoad')
        cfg = generate_cfg(method_instructions, cfg_info_provider, True)
        cfg.describe()
        # for method_instructions in methods_instructions:
        #     generate_cfg(method_instructions, None)

# Reference:
# > https://zhuanlan.zhihu.com/p/24858664
