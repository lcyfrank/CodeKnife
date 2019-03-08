from models.mach_object import *
from interpreters.inner_Interpreter import *
from datetime import datetime
from multiprocessing import Pool, Lock
from models.inner_instruction import *
from cfg_generator import *
from utils import sorted_list_for_hex_string
from tqdm import tqdm

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

methods_instruction_cache = {}  # {address: method_instruction}


def _disasm_specified_function(arch, mode, machine_code, address, base_address, slice_address):
    code = machine_code[address - base_address:]
    current_function = []

    model = Cs(arch=arch, mode=mode)
    model.detail = True

    last_addr = address - 4
    while last_addr - address + 4 < len(code):
        last_addr += 4
        temp_code = code[last_addr - address:]

        count = 0
        time_1 = datetime.now()
        time_2 = datetime.now()
        for insn in model.disasm(temp_code, last_addr):
            if count % 2 == 0:
                time_1 = datetime.now()
                print((time_1 - time_2).microseconds)
            else:
                time_2 = datetime.now()
                print((time_2 - time_1).microseconds)
            count += 1

            last_addr = insn.address
            print(len(slice_address))
            if hex(insn.address) in slice_address:
                pass
            #     if len(current_function) != 0:
            #         return current_function
            #     current_function.append(insn)
            # else:
            #     current_function.append(insn)
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
    # progress_bar = tqdm(total=len(slice_address))

    # if len(machine_code) > each_trunk:
    #     # 开子进程
    #     all_functions = []
    #     process_count = len(machine_code) // each_trunk + 1
    #     process_count = 4
    #     process_pool = Pool()
    #     for i in range(process_count):
    #         machine_code_begin = i * each_trunk
    #         machine_code_end = i * each_trunk + each_trunk
    #         if machine_code_end >= len(machine_code):
    #             machine_code_end = len(machine_code) - 1
    #         sub_machine_code = machine_code[machine_code_begin:machine_code_end]
    #         part_base_address = base_addr + i * each_trunk
    #         process_pool.apply_async(_sub_slice_handle, args=(i, arch, mode, sub_machine_code, part_base_address, slice_address))
    #     process_pool.close()
    #     process_pool.join()
    #     print(len(process_sub_functions))
    #     for i in range(process_count):
    #         if i in process_sub_functions:
    #             for f in process_sub_functions[i]:
    #                 print(f)
    #                 all_functions.append(f)
    #         if i in process_remain_instructions and len(process_remain_instructions[i]) != 0:  # 这一个块还没有结束，需要和下一个块的第一个方法合起来
    #             remain_instructions = process_remain_instructions[i]
    #             if i + 1 < len(process_sub_functions):
    #                 for insn in process_sub_functions[i + 1][0]:
    #                     remain_instructions.append(insn)
    #                 process_sub_functions[i + 1] = process_sub_functions[i + 1][1:]
    #             all_functions.append(remain_instructions)
    #     print(len(all_functions))
    #     return all_functions
    # else:
    # 不用开子进程了
    model = Cs(arch=arch, mode=mode)
    model.detail = True

    all_functions = []
    current_function = []
    last_addr = base_addr - 4
    slice_addr = int(slice_address[0], 16)  # 当前的函数/方法边界

    fm_count = 0

    while last_addr - base_addr + 4 < len(machine_code):
        last_addr += 4
        temp_machine_code = machine_code[last_addr - base_addr:]
        for insn in model.disasm(temp_machine_code, last_addr):
            last_addr = insn.address
            # print(hex(last_addr))
            if last_addr < slice_addr:
                current_function.append(insn)
            elif last_addr == slice_addr:
                if len(current_function) != 0:
                    all_functions.append(current_function)
                    methods_instruction_cache[hex(current_function[0].address)] = current_function
                    current_function = []
                fm_count += 1
                # progress_bar.update(1)
                slice_addr = int(slice_address[fm_count], 16)
                current_function.append(insn)
            else:  # >
                while last_addr > slice_addr:
                    fm_count += 1
                    slice_addr = int(slice_address[fm_count], 16)
                if last_addr == slice_addr:
                    if len(current_function) != 0:
                        all_functions.append(current_function)
                        methods_instruction_cache[hex(current_function[0].address)] = current_function
                        current_function = []
                    fm_count += 1
                    # progress_bar.update(1)
                    slice_addr = int(slice_address[fm_count], 16)
                    current_function.append(insn)
                else:
                    current_function.append(insn)
            # if hex(insn.address) in slice_address:
            #     if len(current_function) != 0:
            #         all_functions.append(current_function)
            #         current_function = []
            #     current_function.append(insn)
            # else:
            #     current_function.append(insn)
    all_functions.append(current_function)
    methods_instruction_cache[hex(current_function[0].address)] = current_function
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


def _analyse_basic_block(block_instruction, identify, mach_info, class_data, inter, add_range):
    if class_data is None:
        class_name = '$Function'
    else:
        class_name = class_data.name
    basic_block = MethodBasicBlockInstructions(identify)
    for i in range(len(block_instruction)):
        cs_insn = block_instruction[i]
        inter.interpret_code(block_instruction, begin=i, end=i+1)  # 执行当前语句

        # 生成语句
        insn_str = hex(cs_insn.address) + '\t' + cs_insn.bytes.hex() + '\t' + cs_insn.mnemonic + '\t' + cs_insn.op_str
        instruction = Instruction(insn_str)
        instruction.address = cs_insn.address

        # if cs_insn.address == 0x10000682c:
        #     inter.current_state()

        if cs_insn.id == ARM64_INS_BL or cs_insn.id == ARM64_INS_BLR:  # 函数调用
            operand = cs_insn.operands[0]  # 获得调用的值
            if operand.type == ARM64_OP_IMM:
                try:
                    _function = mach_info.functions[hex(operand.imm)]  # 取得调用的函数
                except Exception as e:
                    continue

                # 解析出函数名
                function_name = mach_info.symbols[hex(_function)]
                if function_name == "_objc_msgSendSuper2":
                    reg1_value = inter.gen_regs[1].value
                    meth_name = mach_info.symbols[hex(reg1_value)]  # 解析出方法名

                    # 处理父类调用的返回值
                    # ！！！！！！！！！！！！！
                    return_type = mach_info.get_return_type_from_method(class_data.super, meth_name)
                    if return_type == '$SELF':
                        return_type = class_name
                    if not return_type == 'void':
                        _g_return_types.append(return_type)
                        inter.modify_regs('0', RETURN_VALUE - (len(_g_return_types) - 1))
                    # 以上处理返回值

                    # ！！！！！！！！！！！！！
                    instruction.goto(class_data.super, meth_name)  # 在 instruction 中可以增加参数，确保后续解析

                elif function_name == "_objc_storeStrong":
                    reg0_value = inter.gen_regs[0].value
                    reg1_value = inter.gen_regs[1].value
                    inter.modify_memory(reg0_value, reg1_value)

                elif function_name == "_objc_msgSend":
                    # 处理普通方法调用
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
                                ivar = class_data.ivars[reg0_value]
                                obj_name = class_name + "->" + ivar.name
                            elif hex(reg0_value) in mach_info.cfstrings:
                                obj_name = "NSString"
                            else:  # static vars
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

                    block_arguments = mach_info.contain_block_arguments(obj_name, meth_name)
                    if len(block_arguments) > 0:  # 参数中有 Block
                        for index in block_arguments:
                            block_value = inter.gen_regs[index].value
                            if hex(block_value) in mach_info.block_methods:
                                block_data = mach_info.block_methods[hex(block_value)]
                                _, block_name = mach_info.methods[hex(block_data.invoke)]
                                instruction.block_callback(block_name)
                            else:
                                # print(hex(block_value))
                                dylib_name = mach_info.symbols[hex(inter.memory[hex(block_value)])]
                                if dylib_name == '__NSConcreteStackBlock':
                                    type = BlockMethodTypeStack
                                    block_data = BlockMethodData(type)
                                    block_data.invoke = inter.memory[hex(block_value + (16 if mach_info.is_64_bit else 12))]
                                    mach_info.methods[hex(block_data.invoke)] = '$Block', hex(block_data.invoke)
                                    instruction.block_callback(hex(block_data.invoke))
                    # ！！！！！！！！！！！！！
                    # 处理返回值
                    return_type = mach_info.get_return_type_from_method(obj_name, meth_name)
                    if return_type == '$SELF':
                        return_type = obj_name
                    if not return_type == 'void':
                        _g_return_types.append(return_type)
                        inter.modify_regs('0', RETURN_VALUE - (len(_g_return_types) - 1))
                    # 以上处理返回值

                    instruction.goto(obj_name, meth_name)  # ！！！！！！！！！！！！！
                else:
                    instruction.goto("$Function", function_name)

                    block_arguments = mach_info.contain_block_arguments('$Function', function_name)
                    if len(block_arguments) > 0:  # 如果参数中有 Block
                        for index in block_arguments:
                            block_value = inter.gen_regs[index].value
                            if hex(block_value) in mach_info.block_methods:
                                block_data = mach_info.block_methods[hex(block_value)]
                                _, block_name = mach_info.methods[hex(block_data.invoke)]
                                instruction.block_callback(block_name)
                            else:
                                # print(inter.saved_state)
                                # inter.current_state()
                                dylib_name = mach_info.symbols[hex(inter.memory[hex(block_value)])]
                                if dylib_name == '__NSConcreteStackBlock':
                                    type = BlockMethodTypeStack
                                    block_data = BlockMethodData(type)
                                    block_data.invoke = inter.memory[hex(block_value + (16 if mach_info.is_64_bit else 12))]
                                    # inter.current_state()
                                    # print(hex(block_value))
                                    # print(hex(block_data.invoke))
                                    mach_info.methods[hex(block_data.invoke)] = '$Block', hex(block_data.invoke)
                                    instruction.block_callback(hex(block_data.invoke))
                    # ！！！！！！！！！！！！！
                    # 处理返回值
                    return_type = mach_info.get_return_type_from_function(function_name)
                    if not return_type == 'void':
                        _g_return_types.append(return_type)
                        inter.modify_regs('0', RETURN_VALUE - (len(_g_return_types) - 1))
                    # 以上处理返回值
        elif cs_insn.id == ARM64_INS_B:
            address_op = cs_insn.operands[-1]
            if len(cs_insn.mnemonic) == 1:  # 无条件跳转
                basic_block.jump_condition = None
                # 无条件跳转出去了是不是也是返回了？
                if address_op.type == ARM64_OP_IMM:
                    jump_address = address_op.imm
                    begin, end = add_range
                    if not (begin <= jump_address <= end):
                        basic_block.is_return = True
            else:
                basic_block.jump_condition = cs_insn.mnemonic
            if address_op.type == ARM64_OP_IMM:
                basic_block.jump_to_block = hex(address_op.imm)
        elif cs_insn.id == ARM64_INS_CBZ or cs_insn.id == ARM64_INS_CBNZ or cs_insn.id == ARM64_INS_TBZ or cs_insn.id == ARM64_INS_TBNZ:
            address_op = cs_insn.operands[-1]
            # 决定跳转条件
            jump_condition = cs_insn.mnemonic + ' '
            condition_op = cs_insn.operands[0]
            if condition_op.type == ARM64_OP_REG:
                reg_name = cs_insn.reg_name(condition_op.reg)
                jump_condition += reg_name
            basic_block.jump_condition = jump_condition
            if address_op.type == ARM64_OP_IMM:
                basic_block.jump_to_block = hex(address_op.imm)
        elif cs_insn.id == ARM64_INS_RET:
            basic_block.insert_instruction(instruction)
            basic_block.is_return = True
            return basic_block
        basic_block.insert_instruction(instruction)
    return basic_block


def _analyse_method(method, mach_info, recursive=True):

    def memory_provider(address):
        try:
            return mach_info.get_memory_content(address, 8)
        except Exception as _:
            return 0

    if hex(method[0].address) not in mach_info.methods:  # pass the functions
        return None
    class_name, method_name = mach_info.methods[hex(method[0].address)]

    # 参数等会儿考虑
    if class_name == '$Function':
        arguments_count = 8  # 如果是函数，假设共有 8 个参数
        arguments = []
    elif class_name == '$Block':
        pass
    else:
        method_arguments = mach_info.get_arguments_from_methd(class_name, method_name)
        print(method_arguments)


        # 传入解释器的参数类型（float, int）
        # 传入解释器的参数(type, length, value)
        # arguments = [( 'int', 8, SELF_POINTER), ('int', 8, CURRENT_SELECTOR)]
    #     if len(method_arguments) > 2:
    #         for i in range(2, len(method_arguments)):
    #             # '@': 'id', '#': 'Class', ':': 'SEL',
    #             # 'c': 'Char', 'i': 'Integer', 's': 'Integer',
    #             # 'l': 'Integer', 'q': 'Integer', 'C': 'Char',
    #             # 'I': 'Integer', 'S': 'Integer', 'L': 'Integer',
    #             # 'Q': 'Integer', 'f': 'Float', 'd': 'Float',
    #             # 'B': 'Bool', 'v': 'None', '*': 'Pointer'
    #             argument_type = method_arguments[i].type
    #             length = method_arguments[i].length
    #
    #             argument = None
    #             if argument_type == 'id' or argument_type == 'Class' or argument_type == 'SEL' or argument_type == 'Pointer':
    #                 argument = ('int', length, SELF_POINTER - i + 1)
    #             elif argument_type == 'Float':
    #                 argument = ('float', length, SELF_POINTER - i + 1)
    #             elif argument_type == 'Char' or argument_type == 'Integer' or argument_type == 'Bool':
    #                 argument = ('int', length, SELF_POINTER - i + 1)
    #             if argument is not None:
    #                 arguments.append(argument)
    #
    #     # for method_argument in method_arguments:
    #     #     print(method_argument.type, method_argument.length)
    #
    #     # arguments_count = method_name.count(':')
    #     # arguments = [SELF_POINTER, CURRENT_SELECTOR]
    #
    # # parameters = [SELF_POINTER, CURRENT_SELECTOR]
    #
    # # 构造一个解释器
    # inter = Interpreter(memory_provider, parameters=arguments)
    #
    # print('Current analyse <%s: %s>' % (class_name, method_name))
    #
    # class_data = None
    # for data in mach_info.class_datas.values():
    #     if data.name == class_name:
    #         class_data = data
    #
    # # 用来代表当前方法
    # method_instructions = MethodInstructions(class_name, method_name)
    #
    # # 将当前方法拆分成基本块
    # basic_blocks_instructions = _slice_basic_block(method)
    #
    # # 判断可达的块
    # reachable_blocks_queue = _analyse_reachable_of_basic_blocks(basic_blocks_instructions)
    #
    # blocks_instructions_queue = []  # 执行队列
    # blocks_instructions_queue.append(basic_blocks_instructions[0])  # 将入口块入队列
    #
    # wait_for_follow_queue = []  # 等待分析后续基本块的当前基本块队列
    # wait_for_follow_count_queue = []  # 等待分析后续基本块的数量队列
    #
    # wait_for_follow = None
    # wait_for_follow_count = 0
    #
    # while len(blocks_instructions_queue) > 0:  # 执行队列不为空
    #
    #     follow_count = 0
    #
    #     if wait_for_follow is None and len(wait_for_follow_queue) > 0:
    #         wait_for_follow = wait_for_follow_queue[0]
    #         wait_for_follow_queue = wait_for_follow_queue[1:]
    #         wait_for_follow_count = wait_for_follow_count_queue[0]
    #         wait_for_follow_count_queue = wait_for_follow_count_queue[1:]
    #
    #     block_instructions = blocks_instructions_queue[0]  # 队尾出队
    #     blocks_instructions_queue = blocks_instructions_queue[1:]
    #     # print(hex(block_instructions[0].address))
    #     # print(hex(inter.sp.value))
    #
    #     if wait_for_follow is not None:
    #         # if block_instructions[0].address == 0x100afc6e8:
    #             # print('lcy', wait_for_follow.identify)
    #         inter.restore_state(wait_for_follow.identify)
    #         wait_for_follow_count -= 1
    #
    #         # 解析跳转条件
    #         if wait_for_follow.jump_condition is not None:
    #             jump_condition = wait_for_follow.jump_condition.split(' ')
    #             if wait_for_follow.jump_to_block == hex(block_instructions[0].address):  # 跳转过去的
    #                 if len(jump_condition) == 1:  # b.le 等等
    #                     # print(jump_condition)
    #                     pass
    #                 else:  # cbz 等等
    #                     # print(jump_condition)
    #                     pass
    #                 pass
    #             else:  # 需要与跳转条件不一样
    #                 pass
    #
    #         if wait_for_follow_count == 0:
    #             wait_for_follow = None
    #
    #     if hex(block_instructions[0].address) in method_instructions.all_blocks:  # 如果这个块被执行过了
    #         continue
    #
    #     # 模拟执行这个基本块
    #     block = _analyse_basic_block(block_instructions, hex(block_instructions[0].address),
    #                                  mach_info, class_data, inter, (method[0].address, method[-1].address))
    #     method_instructions.all_blocks[block.identify] = block
    #
    #     # 执行完毕，获取其后续块（跳转过去的块或者下一个块）
    #     if not block.is_return:
    #         current_index = basic_blocks_instructions.index(block_instructions)
    #         if current_index + 1 < len(basic_blocks_instructions):
    #             next_block_instructions = basic_blocks_instructions[current_index + 1]
    #             if next_block_instructions[0].address in reachable_blocks_queue:  # 只有在该块可达的时候才有必要归入 next_block
    #                 blocks_instructions_queue.append(next_block_instructions)  # 入队列
    #                 follow_count += 1
    #
    #                 next_block_address = next_block_instructions[0].address
    #                 block.next_block = hex(next_block_address)
    #
    #     if block.jump_to_block is not None:
    #         for jump_to_block_instructions in basic_blocks_instructions:
    #             if hex(jump_to_block_instructions[0].address) == block.jump_to_block:
    #                 blocks_instructions_queue.append(jump_to_block_instructions)  # 入队列
    #                 follow_count += 1
    #                 break
    #
    #     if follow_count > 0:
    #         wait_for_follow_queue.append(block)
    #         wait_for_follow_count_queue.append(follow_count)
    #         inter.save_state(block.identify)  # 保存此时的寄存器状态
    #
    #     # 如果入口块是空的，添加入口块
    #     if method_instructions.entry_block is None:
    #         method_instructions.entry_block = block
    #
    # return method_instructions


# 0 means 64-bit
# 1 means 32-bit
# 2 means both
# Note: if only one arch, just analysis that arch
def static_analysis(binary_file, arch=0):

    # 用来解析动态库
    def macho_file_provider(file_path):
        if '/' in binary_file:
            path_components = binary_file.split('/')
            path_components = path_components[:-1]
            path = '/'.join(path_components)
            file_path = path + '/' + file_path
            return open(file_path, 'rb')
        else:
            return open(file_path, 'rb')

    mach_o_file = open(binary_file, 'rb')

    if arch == 0:
        mode = Analyse_64_Bit
    elif arch == 1:
        mode = Analyse_32_Bit
    else:
        mode = Analyse_Both

    mach_container = MachContainer(mach_o_file.read(), file_provider=macho_file_provider, mode=mode)

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

        sorted_slice_addresses = sorted_list_for_hex_string(slice_addresses)
        # address = mach_info.get_method_address('ThreadQueue', 'RunWithTarget:selector:object:')

            # if method_instruction[0].address == 0x10166b9e0:
            #     print(mach_info.methods[hex(method_instruction[0].address)])
            # if hex(method_instruction[0].address) in mach_info.methods:
            #     print(mach_info.methods[hex(method_instruction[0].address)])
            # else:
            #     print(mach_info.functions[hex(method_instruction[0].address)])
        # print('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
        # print(sorted_list_for_hex_string(slice_addresses))
        # print('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb')

        # print(len(mach_info.methods.keys()))

        # address = mach_info.get_method_address('PDDCrashManager', 'extractDataFromCrashReport:keyword:')
        # address = mach_info.get_method_address('PDDCrashManager', 'setup')
        # address = mach_info.get_method_address('KSCrashInstallationConsole', 'sharedInstance')
        # address = mach_info.get_method_address('LuaViewController', 'attachSceneIfPossible')
        # address = mach_info.get_method_address('LuaViewController', 'viewDidLoad')
        # address = mach_info.get_method_address('AppDelegate', 'application:didFinishLaunchingWithOptions:')
        # address = mach_info.get_method_address('KSCrashReportFilterPipeline', 'initWithFiltersArray:')
        # address = mach_info.get_method_address('ABKCategoryManageViewController', 'deleteButtonClick:')
        # address = mach_info.get_method_address('ABKWelcomeViewController', 'viewDidLoad')
        # address = mach_info.get_method_address('PDDNetworkInterceptor', 'sharedInstance')
        # address = mach_info.get_method_address('ViewController', 'viewDidLoad')
        # address = mach_info.get_method_address('WBMAppDelegate', 'application:didFinishLaunchingWithOptions:')
        # address = mach_info.get_method_address('WBMModuleManager', 'shareManager')
        # address = mach_info.get_method_address('ABKUserInfo', 'init')

        def cfg_provider(class_name, imp_name):
            # print(class_name, imp_name)
            instruction = MethodStorage.get_instructions(class_name, imp_name)
            if instruction is None:
                address = mach_info.get_method_address(class_name, imp_name)
                if address is not None:
                    method = _disasm_specified_function(arch, mode, mach_info.text, int(address, 16), mach_info.text_addr, slice_addresses)
                    # print(method)
                    instruction = _analyse_method(method, mach_info)
                    MethodStorage.insert_instructions(instruction)
                else:
                    # 在动态库中找方法
                    dylib_key = '_OBJC_CLASS_$_' + class_name
                    if dylib_key in mach_info.dylib_frameworks_pair:
                        dylib_mach_info = mach_info.get_dylib_frameworks(mach_info.dylib_frameworks_pair[dylib_key])
                        if dylib_mach_info is not None:
                            dylib_slice_address = list(dylib_mach_info.methods.keys())
                            dylib_slice_address += list(dylib_mach_info.functions.keys())
                            address = dylib_mach_info.get_method_address(class_name, imp_name)
                            if address is not None:
                                method = _disasm_specified_function(arch, mode, dylib_mach_info.text, int(address, 16), dylib_mach_info.text_addr, dylib_slice_address)
                                instruction = _analyse_method(method, dylib_mach_info)
                                MethodStorage.insert_instructions(instruction)
                    # print(mach_info.dylib_frameworks_pair)
                    # framework_path = mach_info.dylib_frameworks_pair[class_name]
                    # print(framework_path)
            return instruction

        print("Start disassemble all methods!")
        method_instructions = _slice_by_function_for_arm64(arch, mode, mach_info.text, mach_info.text_addr, sorted_slice_addresses)
        print("Disassemble complete!")
        for method_instruction in method_instructions:
            _analyse_method(method_instruction, mach_info)
        # address = mach_info.get_method_address('PDDCrashManager', 'extractDataFromCrashReport:keyword:')
        # address = mach_info.get_method_address('PDDSafeSwizzleManager', 'init')
        # if address is not None:
        #     method = _disasm_specified_function(arch, mode, mach_info.text, int(address, 16), mach_info.text_addr, slice_addresses)
#             instruction = _analyse_method(method, mach_info)
#             # instruction.describe()
#             MethodStorage.insert_instructions(instruction)
#             # MethodStorage.list_all()
# #         method_instructions = MethodStorage.get_instructions('ABKWelcomeViewController', 'viewDidLoad')
#             cfg = generate_cfg(instruction, cfg_provider, False)
#             # cfg.describe()
#             cfg.view()
#         # for method_instructions in methods_instructions:
#         #     generate_cfg(method_instructions, None)
#
# Reference:
# > https://zhuanlan.zhihu.com/p/24858664
