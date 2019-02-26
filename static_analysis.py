from models.mach_object import *
from interpreters.inner_Interpreter import *
from datetime import datetime
from multiprocessing import Pool, Lock
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


lock = Lock()
process_remain_instructions = {}  # {trunk_id: remain_instruction}
process_sub_functions = {}  # {trunk_id: sub_functions}


def _disasm_specified_function(arch, mode, machine_code, address, base_address, slice_address):
    code = machine_code[address - base_address:]
    current_function = []

    model = Cs(arch=arch, mode=mode)
    model.detail = True

    last_addr = address - 4
    while last_addr - address + 4 < len(code):
        last_addr += 4
        temp_code = code[last_addr - address:]
        for insn in model.disasm(temp_code, last_addr):
            last_addr = insn.address
            if hex(insn.address) in slice_address:
                if len(current_function) != 0:
                    return current_function
                current_function.append(insn)
            else:
                current_function.append(insn)
    return current_function


def _sub_slice_handle(trunk_id, arch, mode, sub_machine_code, part_base_addr, slice_address):
    global lock
    global process_remain_instructions
    global process_sub_functions

    model = Cs(arch=arch, mode=mode)
    model.detail = True

    sub_functions = []
    current_function = []
    last_addr = part_base_addr - 4

    while last_addr - part_base_addr + 4 < len(sub_machine_code):
        last_addr += 4
        temp_sub_machine_code = sub_machine_code[last_addr - part_base_addr:]
        for insn in model.disasm(temp_sub_machine_code, last_addr):
            last_addr = insn.address
            if hex(insn.address) in slice_address:
                if len(current_function) != 0:
                    sub_functions.append(current_function)
                    current_function = []
                current_function.append(insn)
            else:
                current_function.append(insn)
    lock.acquire()
    process_sub_functions[trunk_id] = sub_functions
    process_remain_instructions[trunk_id] = current_function
    print(len(process_sub_functions))
    lock.release()


def _slice_by_function_for_arm64(arch, mode, machine_code, base_addr, slice_address):
    each_trunk = 0x4000
    global process_remain_instructions
    global process_sub_functions

    if len(machine_code) > each_trunk:
        # 开子进程
        all_functions = []
        process_count = len(machine_code) // each_trunk + 1
        process_count = 4
        process_pool = Pool()
        for i in range(process_count):
            machine_code_begin = i * each_trunk
            machine_code_end = i * each_trunk + each_trunk
            if machine_code_end >= len(machine_code):
                machine_code_end = len(machine_code) - 1
            sub_machine_code = machine_code[machine_code_begin:machine_code_end]
            part_base_address = base_addr + i * each_trunk
            process_pool.apply_async(_sub_slice_handle, args=(i, arch, mode, sub_machine_code, part_base_address, slice_address))
        process_pool.close()
        process_pool.join()
        print(len(process_sub_functions))
        for i in range(process_count):
            if i in process_sub_functions:
                for f in process_sub_functions[i]:
                    print(f)
                    all_functions.append(f)
            if i in process_remain_instructions and len(process_remain_instructions[i]) != 0:  # 这一个块还没有结束，需要和下一个块的第一个方法合起来
                remain_instructions = process_remain_instructions[i]
                if i + 1 < len(process_sub_functions):
                    for insn in process_sub_functions[i + 1][0]:
                        remain_instructions.append(insn)
                    process_sub_functions[i + 1] = process_sub_functions[i + 1][1:]
                all_functions.append(remain_instructions)
        print(len(all_functions))
        return all_functions
    else:
        # 不用开子进程了
        model = Cs(arch=arch, mode=mode)
        model.detail = True

        all_functions = []
        current_function = []
        last_addr = base_addr - 4

        while last_addr - base_addr + 4 < len(machine_code):
            last_addr += 4
            temp_machine_code = machine_code[last_addr - base_addr:]
            for insn in model.disasm(temp_machine_code, last_addr):
                last_addr = insn.address
                if hex(insn.address) in slice_address:
                    if len(current_function) != 0:
                        all_functions.append(current_function)
                        current_function = []
                    current_function.append(insn)
                else:
                    current_function.append(insn)
        all_functions.append(current_function)
        return all_functions


def _slice_basic_block(method):

    slice_address = []
    current_slice_address = method[0].address

    slice_address.append(hex(current_slice_address))
    for i in range(len(method)):
        cs_insn = method[i]
        if (cs_insn.id == ARM64_INS_B or
            cs_insn.id == ARM64_INS_CBZ or
            cs_insn.id == ARM64_INS_CBNZ or
            cs_insn.id == ARM64_INS_TBZ or
            cs_insn.id == ARM64_INS_TBNZ):
            address_op = cs_insn.operands[-1]
            if address_op.type == ARM64_OP_IMM:
                j_address = address_op.imm

                if method[0].address <= j_address <= method[-1].address:
                    slice_address.append(hex(j_address))
            if i < len(method) - 1:
                slice_address.append(hex(method[i + 1].address))

    slice_address = list({}.fromkeys(slice_address).keys())

    basic_blocks = []
    current_basic_block = []
    # current_basic_block_address = None

    for cs_insn in method:
        if hex(cs_insn.address) in slice_address:
            if len(current_basic_block) != 0:
                # basic_blocks[hex(current_basic_block_address)] = current_basic_block
                basic_blocks.append(current_basic_block)

            current_basic_block = []
            # current_basic_block_address = cs_insn.address
        current_basic_block.append(cs_insn)
    if len(current_basic_block) != 0:
        basic_blocks.append(current_basic_block)
        # basic_blocks[hex(current_basic_block_address)] = current_basic_block
    return basic_blocks


def _contain_return_of_block(block):
    for insn in block:
        if insn.id == ARM64_INS_RET:
            return True
    return False


# 分析基本块的可达性
def _analyse_reachable_of_basic_blocks(basic_blocks):
    reachable = []
    wait_to_analyse = []

    reachable.append(basic_blocks[0][0].address)
    wait_to_analyse.append(basic_blocks[0])

    while len(wait_to_analyse) > 0:
        # pop
        block = wait_to_analyse[0]
        wait_to_analyse = wait_to_analyse[1:]

        if _contain_return_of_block(block):  # 如果这个 block 包含 return 语句，就直接不分析了
            continue

        last_id = block[-1].id
        if last_id != ARM64_INS_B or (last_id == ARM64_INS_B and len(block[-1].mnemonic) > 1):
            block_index = basic_blocks.index(block)
            if block_index < len(basic_blocks) - 1:
                next_block = basic_blocks[block_index + 1]
                reachable.append(next_block[0].address)
                wait_to_analyse.append(next_block)

        if (last_id == ARM64_INS_B or
            last_id == ARM64_INS_CBZ or
            last_id == ARM64_INS_CBNZ or
            last_id == ARM64_INS_TBZ or
            last_id == ARM64_INS_TBNZ):
            address_op = block[-1].operands[-1]
            if address_op.type == ARM64_OP_IMM:
                j_address = address_op.imm
                if (basic_blocks[0][0].address <= j_address <= basic_blocks[-1][-1].address and
                    j_address not in reachable):
                    reachable.append(j_address)
                    # 找那个 block
                    for next_block in basic_blocks:
                        if next_block[0].address == j_address:
                            wait_to_analyse.append(next_block)
                            break
    return reachable


def _analyse_basic_block(block_instruction, identify, mach_info, class_data, class_name, method_name, inter):
    basic_block = MethodBasicBlockInstructions(identify)
    for i in range(len(block_instruction)):
        inter.interpret_code(block_instruction, begin=i, end=i+1)
        cs_insn = block_instruction[i]

        if cs_insn.address == 0x1001f910c:
            inter.current_state()

        insn_str = hex(cs_insn.address) + '\t' + cs_insn.bytes.hex() + '\t' + cs_insn.mnemonic + '\t' + cs_insn.op_str
        instruction = Instruction(insn_str)
        instruction.address = cs_insn.address
        if cs_insn.id == ARM64_INS_BL or cs_insn.id == ARM64_INS_BLR:
            operand = cs_insn.operands[0]
            if operand.type == ARM64_OP_IMM:
                try:
                    _function = mach_info.functions[hex(operand.imm)]
                except Exception as e:
                    continue
                function_name = mach_info.symbols[hex(_function)]
                if function_name == "_objc_msgSendSuper2":
                    # 调用父类方法也要处理返回值
                    reg1_value = inter.gen_regs[1].value
                    meth_name = mach_info.symbols[hex(reg1_value)]
                    return_type = mach_info.get_return_type_from_method(class_data.super, meth_name)

                    if return_type == '$SELF':
                        return_type = class_name
                    # if obj_name == 'UIScreen':
                    #     print(meth_name)
                    #     print(return_type)
                    # 返回值这一块还得处理
                    # if return_type == 'id' or return_type == 'UILabel':  # Now is id
                    if not return_type == 'void':
                        _g_return_types.append(return_type)
                        inter.modify_regs('0', RETURN_VALUE - (len(_g_return_types) - 1))
                    instruction.goto(class_data.super, meth_name)

                elif function_name == "_dispatch_once":  # 实际上就可以把这个指令换成 Block 内部的指令
                    instruction.goto('$Function', function_name)
                    # 因为 dispatch_once 获得了一个 Block 进行调用
                    reg1_value = inter.gen_regs[1].value
                    block_data = mach_info.block_methods[hex(reg1_value)]
                    _, block_name = mach_info.methods[hex(block_data.invoke)]
                    # 这样对 Block，之后也可以直接使用查询方法的形式进行展示
                    instruction.block_callback(block_name)
                elif function_name == "_objc_msgSend":
                    reg0_value = inter.gen_regs[0].value
                    reg1_value = inter.gen_regs[1].value
                    if reg0_value == SELF_POINTER:
                        obj_name = class_name
                    elif reg0_value <= RETURN_VALUE:
                        obj_name = _g_return_types[RETURN_VALUE - reg0_value]
                    elif reg0_value < SELF_POINTER:
                        obj_name = "PARAMETERS_" + str(SELF_POINTER - reg0_value - 1)
                        # if cs_insn.address == 0x100007e8c:
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
                                try:
                                    static_name = mach_info.statics[hex(reg0_value)]
                                    obj_name = mach_info.symbols[hex(static_name)]
                                except Exception as e:
                                    print("Some error happens during analysis in get value in register 0 (Instance)")
                                    print(str(e))
                                    print("Current instruction address is %s" % hex(cs_insn.address))
                                    obj_name = 'id'

                    try:
                        meth_name = mach_info.symbols[hex(reg1_value)]
                    except Exception as e:
                        print("Some error happens during analysis in get value in register 1 (Method)")
                        print(str(e))
                        print("Current instruction address is %s" % hex(cs_insn.address))
                        break

                    return_type = mach_info.get_return_type_from_method(obj_name, meth_name)
                    if return_type == '$SELF':
                        return_type = class_name
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
        elif cs_insn.id == ARM64_INS_B:
            address_op = cs_insn.operands[-1]
            if len(cs_insn.mnemonic) == 1:  # 无条件跳转
                basic_block.jump_condition = False
                # 无条件跳转出去了是不是也是返回了？
                # 现在先处理无条件跳转到一些意味着返回的方法
                if address_op.type == ARM64_OP_IMM:
                    jump_address = address_op.imm
                    if hex(jump_address) in mach_info.functions:  # jump to a function
                        function = hex(mach_info.functions[hex(jump_address)])
                        function_name = mach_info.symbols[function]
                        if (function_name == '_objc_autoreleaseReturnValue' or
                            function_name == '_objc_retainAutoreleaseReturnValue'):
                            basic_block.is_return = True
            else:
                basic_block.jump_condition = True
            if address_op.type == ARM64_OP_IMM:
                basic_block.jump_to_block = hex(address_op.imm)
        elif cs_insn.id == ARM64_INS_CBZ or cs_insn.id == ARM64_INS_CBNZ or cs_insn.id == ARM64_INS_TBZ or cs_insn.id == ARM64_INS_TBNZ:
            address_op = cs_insn.operands[-1]
            basic_block.jump_condition = True
            if address_op.type == ARM64_OP_IMM:
                basic_block.jump_to_block = hex(address_op.imm)
        elif cs_insn.id == ARM64_INS_RET:
            basic_block.insert_instruction(instruction)
            basic_block.is_return = True
            return basic_block
        basic_block.insert_instruction(instruction)
    return basic_block


def _analyse_method(method, mach_info):

    def memory_provider(address):
        try:
            return mach_info.get_memory_content(address, 8)
        except Exception as _:
            return 0

    if hex(method[0].address) not in mach_info.methods:  # pass the functions
        return None
    class_name, method_name = mach_info.methods[hex(method[0].address)]
    parameters = [SELF_POINTER, CURRENT_SELECTOR]
    parameters_count = method_name.count(':')  # OC 的方法通过统计冒号个数来获得参数个数
    for p in range(parameters_count):
        parameters.append(SELF_POINTER - p - 1)
    inter = Interpreter(memory_provider, parameters=parameters)

    print('Current analyse <%s: %s>' % (class_name, method_name))

    class_data = None
    for data in mach_info.class_datas.values():
        if data.name == class_name:
            class_data = data
    method_instructions = MethodInstructions(class_name, method_name)
    # last_address = method[-1].address

    # 拆分成基本块
    basic_blocks_instructions = _slice_basic_block(method)
    # 判断可达的块
    reachable_blocks_queue = _analyse_reachable_of_basic_blocks(basic_blocks_instructions)

    # def convert_to_hex(i):
    #     return hex(i)
    # print(list(map(convert_to_hex, reachable_blocks_queue)))

    for block_instructions in basic_blocks_instructions:
        if block_instructions[0].address in reachable_blocks_queue:  # if this block can be reached
            block = _analyse_basic_block(block_instructions, hex(block_instructions[0].address), mach_info, class_data,
                                         class_name, method_name, inter)

            method_instructions.all_blocks[block.identify] = block
            MethodBasicBlockStorage.insert_instructions(block)

            # 如果挨近的下一个块是可到达的，则添加下一个块
            current_index = basic_blocks_instructions.index(block_instructions)
            while current_index < len(basic_blocks_instructions) - 1:
                next_block_instructions = basic_blocks_instructions[current_index + 1]
                next_block_address = next_block_instructions[0].address
                if next_block_address in reachable_blocks_queue:
                    block.next_block = hex(next_block_address)  # set next block
                    break
                current_index += 1

            # 如果当前块 return 了，则结束
            if block.is_return:
                if method_instructions.entry_block is None:
                    method_instructions.entry_block = block
                continue

            # 如果入口块是空的，添加入口块
            if method_instructions.entry_block is None:
                method_instructions.entry_block = block

    # print(method_instructions.all_blocks)

    return method_instructions


def static_analysis(binary_file):
    mach_o_file = open(binary_file, 'rb')
    mach_container = MachContainer(mach_o_file.read())
    for mach_info in mach_container.mach_objects:
        # print(mach_info.methods)
        # print(mach_info.methods_type[0])
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

        slice_addresses = list(mach_info.methods.keys())
        slice_addresses += list(mach_info.functions.keys())

        # address = mach_info.get_method_address('PDDCrashManager', 'extractDataFromCrashReport:keyword:')
        # address = mach_info.get_method_address('PDDCrashManager', 'setup')
        # address = mach_info.get_method_address('KSCrashInstallationConsole', 'sharedInstance')
        address = mach_info.get_method_address('KSCrashInstallationConsole', 'init')

        def cfg_provider(class_name, imp_name):
            instruction = MethodStorage.get_instructions(class_name, imp_name)
            if instruction is None:
                address = mach_info.get_method_address(class_name, imp_name)
                if address is not None:
                    method = _disasm_specified_function(arch, mode, mach_info.text, int(address, 16), mach_info.text_addr, slice_addresses)
                    instruction = _analyse_method(method, mach_info)
                    MethodStorage.insert_instructions(instruction)
            return instruction

        # address = mach_info.get_method_address('PDDCrashManager', 'extractDataFromCrashReport:keyword:')
        # address = mach_info.get_method_address('PDDSafeSwizzleManager', 'init')
        if address is not None:
            method = _disasm_specified_function(arch, mode, mach_info.text, int(address, 16), mach_info.text_addr, slice_addresses)
            instruction = _analyse_method(method, mach_info)
            # instruction.describe()
            MethodStorage.insert_instructions(instruction)
            # MethodStorage.list_all()
#         method_instructions = MethodStorage.get_instructions('ABKWelcomeViewController', 'viewDidLoad')
            cfg = generate_cfg(instruction, cfg_provider, True)
            # cfg.describe()
            cfg.view()
#         # for method_instructions in methods_instructions:
#         #     generate_cfg(method_instructions, None)
#
# # Reference:
# # > https://zhuanlan.zhihu.com/p/24858664
