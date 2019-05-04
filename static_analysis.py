from models.mach_object import *
from models.macho_method_hub import *
from interpreters.inner_Interpreter import *
from datetime import datetime
from multiprocessing import Pool, Lock, Manager
from models.inner_instruction import *
from cfg_generator import *
from utils import sorted_list_for_hex_string
from tqdm import tqdm
from checker.paste_checker import *
from checker.storage_checker import *
from checker.keychain_checker import *
from checker.background_checker import *
from checker.hotfix_checker import *
import os, shutil

# Constant
FA_CPU_TYPE_KEY = 'cputype'
FA_CPU_SUBTYPE_KEY = 'cpu_subtype'
FA_OFFSET_KEY = 'offset'
FA_SIZE_KEY = 'size'
FA_ALIGN_KEY = 'align'

_g_return_types = []
_g_current_context = ()

methods_hubs = []  # [method_hub]


def _disasm_specified_function(arch, mode, machine_code, address, base_address, slice_address):
    slice_address = set(slice_address)  # 使用 set，加快查询速度
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


def _slice_by_function_for_arm64(arch, mode, machine_code, base_addr, slice_address, method_hub=None):
    model = Cs(arch=arch, mode=mode)
    model.detail = True

    all_functions = []
    current_function = []
    last_addr = base_addr - 4
    slice_addr = int(slice_address[0], 16)  # 当前的函数/方法边界

    fm_count = 0

    progress_bar = tqdm(total=len(machine_code))

    while last_addr - base_addr + 4 < len(machine_code):
        last_addr += 4
        progress_bar.update(4)
        temp_machine_code = machine_code[last_addr - base_addr:]
        for insn in model.disasm(temp_machine_code, last_addr):
            last_addr = insn.address
            progress_bar.update(4)
            if last_addr < slice_addr:
                current_function.append(insn)
            elif last_addr == slice_addr:
                if len(current_function) != 0:
                    all_functions.append(current_function)
                    method_hub.insert_cs_insn(current_function)
                    current_function = []
                fm_count += 1
                slice_addr = int(slice_address[fm_count], 16)
                current_function.append(insn)
            else:  # >
                while last_addr > slice_addr:
                    fm_count += 1
                    slice_addr = int(slice_address[fm_count], 16)
                if last_addr == slice_addr:
                    if len(current_function) != 0:
                        all_functions.append(current_function)
                        method_hub.insert_cs_insn(current_function)
                        current_function = []
                    fm_count += 1
                    slice_addr = int(slice_address[fm_count], 16)
                    current_function.append(insn)
                else:
                    current_function.append(insn)

    progress_bar.close()
    if len(current_function) > 0:
        all_functions.append(current_function)
        method_hub.insert_cs_insn(current_function)
    return all_functions


def _slice_basic_block(method):

    slice_address = set([])
    current_slice_address = method[0].address

    minimal_address = method[0].address
    maximal_address = method[-1].address

    slice_address.add(hex(current_slice_address))
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

                if minimal_address <= j_address <= maximal_address:
                    slice_address.add(hex(j_address))
            if i < len(method) - 1:
                slice_address.add(hex(method[i + 1].address))
    basic_blocks = {}
    basic_blocks_address = []
    current_basic_block = []

    for cs_insn in method:
        if hex(cs_insn.address) in slice_address:  # 当前地址是可拆分地址
            if len(current_basic_block) != 0:
                # basic_blocks[hex(current_basic_block_address)] = current_basic_block
                cs_insn_address = hex(current_basic_block[0].address)
                basic_blocks[cs_insn_address] = current_basic_block
                basic_blocks_address.append(cs_insn_address)
            current_basic_block = []
        current_basic_block.append(cs_insn)
        if cs_insn.id == ARM64_INS_RET:  # 如果当前指令是 return 指令
            current_basic_block.append(cs_insn)
            cs_insn_address = hex(current_basic_block[0].address)
            basic_blocks[cs_insn_address] = current_basic_block
            basic_blocks_address.append(cs_insn_address)
            current_basic_block = []

    if len(current_basic_block) != 0:
        cs_insn_address = hex(current_basic_block[0].address)
        basic_blocks[cs_insn_address] = current_basic_block
        basic_blocks_address.append(cs_insn_address)
    return basic_blocks_address, basic_blocks


# 分析基本块的可达性
def _analyse_reachable_of_basic_blocks(basic_blocks_keys, basic_blocks, method_range):
    reachable = set([])
    wait_to_analyse = []
    block_index_array = []

    basic_block_key = basic_blocks_keys[0]
    reachable.add(int(basic_block_key, 16))

    wait_to_analyse.append(basic_blocks[basic_block_key])
    block_index_array.append(0)

    while len(wait_to_analyse) > 0:
        # pop
        block = wait_to_analyse[0]
        wait_to_analyse = wait_to_analyse[1:]

        block_index = block_index_array[0]
        block_index_array = block_index_array[1:]

        last_id = block[-1].id
        if last_id == ARM64_INS_RET:  # 如果这个 block 包含 return 语句，就直接不分析了
            continue

        if last_id != ARM64_INS_B or (last_id == ARM64_INS_B and len(block[-1].mnemonic) > 1):  # 这个是有条件跳转
            if block_index < len(basic_blocks_keys) - 1:
                next_block_key = basic_blocks_keys[block_index + 1]
                reachable.add(int(next_block_key, 16))
                next_block = basic_blocks[next_block_key]

                wait_to_analyse.append(next_block)
                block_index_array.append(block_index + 1)

        if (last_id == ARM64_INS_B or
            last_id == ARM64_INS_CBZ or
            last_id == ARM64_INS_CBNZ or
            last_id == ARM64_INS_TBZ or
            last_id == ARM64_INS_TBNZ):
            address_op = block[-1].operands[-1]
            if address_op.type == ARM64_OP_IMM:
                j_address = address_op.imm

                minimal_address, maximal_address = method_range
                if (minimal_address <= j_address <= maximal_address and
                    j_address not in reachable):
                    reachable.add(j_address)
                    # 找那个 block
                    if hex(j_address) in basic_blocks:
                        next_block = basic_blocks[hex(j_address)]
                        wait_to_analyse.append(next_block)
                        block_index_array.append(basic_blocks_keys.index(hex(j_address)))  # 这里有个查找
    return reachable


def get_obj_name(mach_info, value, class_name, class_data):
    if value == SELF_POINTER:  # 自己的方法
        return class_name
    if value <= RETURN_VALUE:  # 某个方法的返回值
        return_index = RETURN_VALUE - value
        if return_index < len(_g_return_types):
            return _g_return_types[return_index]
        return 'id'
    if value < SELF_POINTER:  # 调用的是某个参数的方法
        return 'PARAMETERS_' + str(SELF_POINTER - value - 1)
    if value < 0:  # 调用的是父类的方法
        if class_data is None:
            return class_name
        else:
            return class_data.super
    obj_name_key = hex(value)

    # 其他类
    if obj_name_key in mach_info.statics_class:  # 静态变量
        obj_name = mach_info.statics_class[obj_name_key]
        return obj_name
    if obj_name_key in mach_info.symbols:  # 直接可以从符号表中获得信息
        obj_name = mach_info.symbols[obj_name_key]
        obj_name_index = obj_name.find('$')
        obj_name = obj_name[obj_name_index + 2:]
        return obj_name
    if obj_name_key in mach_info.class_datas:  # 调用的是某个类
        obj_data = mach_info.class_datas[obj_name_key]
        return obj_data.name

    if class_data is not None and 1 <= value // 0x8 <= len(class_data.ivars):  # 类中的变量
        ivar_index = value // 0x8 - 1
        ivar = class_data.ivars[ivar_index]
        return ivar._type

    if hex(value) in mach_info.cfstrings:  # 某个字符串的方法
        return "NSString"
    if hex(value) in mach_info.statics:  # 静态变量
        static_name = mach_info.statics[hex(value)]
        return mach_info.symbols[hex(static_name)]

    # print("Some error happens during analysis in get value in register 0 (Instance) %d" % value)
    return 'id'


def handle_method_call(mach_info, class_data, class_name, method_name, inter, method_hub, instruction, recurive_stack=None, method=True, function_name=None):
    global _g_current_context
    if recurive_stack is not None:
        r_stack = recurive_stack.copy()
    else:
        r_stack = set([])

    if method:
        # !!!!!!
        if class_data is None:  # 分类或者 Block
            pass
            # 分类中的方法，再说
        else:
            class_name = class_data.name
        reg0_value = inter.gen_regs[0].value
        reg1_value = inter.gen_regs[1].value
        # 从寄存器中获得方法的调用者
        caller_name = get_obj_name(mach_info, reg0_value, class_name, class_data)
        try:
            meth_name = mach_info.symbols[hex(reg1_value)]
        except Exception as e:
            # print("Some error happens during analysis in get value in register 1 (Method)")
            # print(str(e))
            return False
        # 处理 Objective-C 中的方法调用相关内容
        # Handle Notification
        if caller_name == 'NSNotificationCenter' and meth_name == 'addObserver:selector:name:object:':
            observer = get_obj_name(mach_info, inter.gen_regs[2].value, class_name, class_data)
            selector = mach_info.symbols[hex(inter.gen_regs[3].value)]

            notification_name_key = hex(inter.gen_regs[4].value)
            if notification_name_key in mach_info.symbols:
                # System notification
                notification = mach_info.symbols[notification_name_key]
            elif notification_name_key in mach_info.cfstrings:
                notification = mach_info.symbols[hex(mach_info.cfstrings[notification_name_key])]
            else:
                notification = 'Unknown'
            mach_info.add_notification_observer(notification, observer, selector)

        # Post Notification
        if caller_name == 'NSNotificationCenter' and meth_name == 'postNotificationName:object:userInfo:':
            notification_name_key = hex(inter.gen_regs[2].value)
            if notification_name_key in mach_info.symbols:
                # System notification
                notification = mach_info.symbols[notification_name_key]
            elif notification_name_key in mach_info.cfstrings:
                notification = mach_info.symbols[hex(mach_info.cfstrings[notification_name_key])]
            else:
                notification = 'Unknown'
            mach_info.post_notification(notification, class_name, method_name)

        # 处理方法中的参数
        method_arguments = mach_info.get_arguments_from_method(caller_name, meth_name)
        for i in range(0, len(method_arguments)):
            # if i == 1:
            #     continue
            argument_type = method_arguments[i].type
            argument = None
            if argument_type == 'id' or argument_type == 'Class' or argument_type == 'SEL' or argument_type == 'Pointer':
                argument = 'int'
            elif argument_type == 'Float':
                argument = 'float'
            elif argument_type == 'Char' or argument_type == 'Integer' or argument_type == 'Bool':
                argument = 'int'

            if argument is None:  # 默认参数为 int 类型
                argument = 'int'

            # 作为参数的时候
            # 从上下文中提取数据变量，来生成数据流依赖
            if argument == 'int':
                context_reg_name = 'gen_' + str(i)
            else:
                context_reg_name = 'float_' + str(i)
            if context_reg_name in inter.context.register_variable:
                var_name = inter.context.register_variable[context_reg_name]
                print(method_name)
                print(meth_name)
                # if meth_name == 'addSubview:':
                #     print('======')
                #     print(inter.context.register_variable)
                #     print(context_reg_name)
                #     print(var_name)
                #     print('======')
                from_item = inter.context.variable_from[var_name]
                print('position: ' + str(i))
                inter.context.add_from_to(var_name, from_item, instruction, i)

    else:
        caller_name = '$Function'
        meth_name = function_name

    # 处理参数中的 Block
    block_arguments, call_it = mach_info.contain_block_arguments(caller_name, meth_name)

    if len(block_arguments) > 0:
        for index in block_arguments:
            block_value = inter.gen_regs[index].value
            if hex(block_value) in mach_info.block_methods:  # Global block
                block_data = mach_info.block_methods[hex(block_value)]
                _, block_name = mach_info.methods[hex(block_data.invoke)]
                instruction.block_callback(block_name)
                # 调用 Block
                if call_it:
                    block_insn = method_hub.get_method_insn('$Block', block_name)
                    if block_insn is None:
                        if ('$Block', block_name) not in r_stack:
                            method_address = mach_info.get_method_address('$Block', block_name)
                            if method_address is not None:
                                block_instruction = method_hub.get_cs_insn(hex(method_address))
                                if block_instruction is not None:
                                    _analyse_method(block_instruction, mach_info, method_hub, recursive_stack=r_stack)
                                else:  # 未分析过的 Block 在 MethodHub 中提取不到
                                    arch, mode = _g_current_context
                                    slice_address = list(mach_info.methods.keys())
                                    slice_address += list(mach_info.functions.keys())
                                    block_instruction = _disasm_specified_function(arch, mode, mach_info.text, method_address, mach_info.text_addr, slice_address)
                                    method_hub.insert_cs_insn(block_instruction)
                                    _analyse_method(block_instruction, mach_info, method_hub, recursive_stack=r_stack)

            else:  # Stack block
                dylib_name = mach_info.symbols[hex(inter.memory[hex(block_value)])]
                if dylib_name == '__NSConcreteStackBlock':
                    type = BlockMethodTypeStack
                    block_data = BlockMethodData(type)
                    block_data.invoke = inter.memory[hex(block_value + (16 if mach_info.is_64_bit else 12))]
                    mach_info.methods[hex(block_data.invoke)] = '$Block', hex(block_data.invoke)
                    instruction.block_callback(hex(block_data.invoke))

                    if call_it:
                        block_insn = method_hub.get_method_insn('$Block', hex(block_data.invoke))
                        if block_insn is None:
                            if ('$Block', hex(block_data.invoke)) not in r_stack:
                                method_address = mach_info.get_method_address('$Block', hex(block_data.invoke))
                                if method_address is not None:
                                    block_instruction = method_hub.get_cs_insn(hex(method_address))
                                    if block_instruction is not None:
                                        _analyse_method(block_instruction, mach_info, method_hub, recursive_stack=r_stack)
                                else:
                                    arch, mode = _g_current_context
                                    slice_address = list(mach_info.methods.keys())
                                    slice_address += list(mach_info.functions.keys())
                                    block_instruction = _disasm_specified_function(arch, mode, mach_info.text, block_data.invoke, mach_info.text_addr, slice_address)
                                    method_hub.insert_cs_insn(block_instruction)
                                    _analyse_method(block_instruction, mach_info, method_hub, recursive_stack=r_stack)
    # 处理返回值
    # 递归调用方法
    method_insn = method_hub.get_method_insn(caller_name, meth_name)
    if method_insn is not None:  # 方法指令不是空
        if len(method_insn.return_type) > 0:
            return_type = method_insn.return_type[0]
        else:
            return_type = 'None'
    else:
        if (caller_name, meth_name) in r_stack:
            return_type = 'id'
        else:
            # 该方法在当前二进制文件中
            method_address = mach_info.get_method_address(caller_name, meth_name)
            if method_address is not None:
                goto_instruction = method_hub.get_cs_insn(hex(method_address))
                if goto_instruction is not None:
                    method_insn = _analyse_method(goto_instruction, mach_info, method_hub, recursive_stack=r_stack)
                    if len(method_insn.return_type) > 0:
                        return_type = method_insn.return_type[0]
                    else:
                        return_type = 'None'
                else:
                    arch, mode = _g_current_context

                    # 根据所有 key 确定分隔地址
                    slice_address = list(mach_info.methods.keys())

                    slice_address += list(mach_info.functions.keys())
                    goto_instruction = _disasm_specified_function(arch, mode, mach_info.text, method_address,
                                                                  mach_info.text_addr, slice_address)
                    method_insn = _analyse_method(goto_instruction, mach_info, method_hub, recursive_stack=r_stack)
                    if len(method_insn.return_type) > 0:
                        return_type = method_insn.return_type[0]
                    else:
                        return_type = 'None'
            else:
                # 该方法在动态库中
                dylib_key = '_OBJC_CLASS_$_' + caller_name
                if dylib_key in mach_info.dylib_frameworks_pair:
                    dylib_mach_info = mach_info.get_dylib_frameworks(
                        mach_info.dylib_frameworks_pair[dylib_key])
                    if dylib_mach_info is not None:
                        dylib_slice_address = list(dylib_mach_info.methods.keys())
                        dylib_slice_address += list(dylib_mach_info.functions.keys())
                        # 从动态库中找到该方法
                        address = dylib_mach_info.get_method_address(caller_name, meth_name)
                        if address is not None:
                            arch, mode = _g_current_context
                            dylib_method = _disasm_specified_function(arch, mode, dylib_mach_info.text, address,
                                                                      dylib_mach_info.text_addr, dylib_slice_address)
                            dylib_method_instruction = _analyse_method(dylib_method, dylib_mach_info,
                                                                       method_hub=method_hub, recursive_stack=r_stack)
                            if len(dylib_method_instruction.return_type) > 0:
                                return_type = dylib_method_instruction.return_type[0]
                            else:
                                return_type = 'None'
                        else:
                            return_type = 'None'
                    else:
                        if method:
                            return_type = mach_info.get_return_type_from_method(caller_name, meth_name)
                        else:
                            return_type = mach_info.get_return_type_from_function(meth_name)
                else:
                    if method:
                        return_type = mach_info.get_return_type_from_method(caller_name, meth_name)
                    else:
                        return_type = mach_info.get_return_type_from_function(meth_name)
    # 返回值
    if return_type == '$SELF':
        return_type = caller_name

    # 作为返回值的时候
    if not return_type == 'None':
        _g_return_types.append(return_type)
        inter.modify_regs('0', RETURN_VALUE - (len(_g_return_types) - 1))
        inter.context.add_variable('gen_0')  # 存储返回值
        inter.context.var_from('var_' + str(inter.context.variable_count - 1), instruction)

    instruction.goto(caller_name, meth_name)  # ！！！！！！！！！！！！！
    return True


def handle_super_method(mach_info, class_data, inter, instruction):
    reg1_value = inter.gen_regs[1].value
    meth_name = mach_info.symbols[hex(reg1_value)]  # 解析出方法名

    # 处理父类调用的返回值
    # ！！！！！！！！！！！！！
    if class_data is None:  # None 的时候通常是分类
        class_name = 'id'
        return_type = 'id'
    else:
        class_name = class_data.name
        return_type = mach_info.get_return_type_from_method(class_data.super, meth_name)

    method_arguments = mach_info.get_arguments_from_method(class_name, meth_name)
    for i in range(0, len(method_arguments)):
        argument_type = method_arguments[i].type
        argument = None
        if argument_type == 'id' or argument_type == 'Class' or argument_type == 'SEL' or argument_type == 'Pointer':
            argument = 'int'
        elif argument_type == 'Float':
            argument = 'float'
        elif argument_type == 'Char' or argument_type == 'Integer' or argument_type == 'Bool':
            argument = 'int'
        if argument is None:  # 默认先预设 int 类型的参数
            argument = 'int'

        # 作为参数的时候
        # 从上下文中提取数据变量，来生成数据流依赖
        if argument == 'int':
            context_reg_name = 'gen_' + str(i)
        else:
            context_reg_name = 'float_' + str(i)

        if context_reg_name in inter.context.register_variable:
            var_name = inter.context.register_variable[context_reg_name]  # 获得变量名
            from_item = inter.context.variable_from[var_name]  # from_item 可能是字符串或者 Instruction 类型
            to_item = instruction
            inter.context.add_from_to(var_name, from_item, to_item, i)

    if return_type == '$SELF':
        return_type = class_name

    # 作为返回值的时候
    if not return_type == 'None':  # 返回值不为空
        _g_return_types.append(return_type)
        inter.modify_regs('0', RETURN_VALUE - (len(_g_return_types) - 1))

        inter.context.add_variable('gen_0')  # 存储返回值
        inter.context.var_from('var_' + str(inter.context.variable_count - 1), instruction)

    instruction.goto(class_name, meth_name)


def _analyse_basic_block(block_instruction, identify, mach_info, class_data, class_name, method_name, inter: Interpreter, add_range, method_hub=None, recursive_stack=set([])):
    r_stack = recursive_stack.copy()

    basic_block = MethodBasicBlockInstructions(identify)
    for i in range(len(block_instruction)):
        cs_insn = block_instruction[i]
        inter.interpret_code(block_instruction, begin=i, end=i+1)  # 执行当前语句
        # if cs_insn.address == 0x10002f998:
        #     ctx = inter.context
        #     print(ctx.data_flow)
        #     print(ctx.variable_from)
        #     print(ctx.register_variable)
        #     print(ctx.memory_variable)
        # 生成语句
        insn_str = hex(cs_insn.address) + '\t' + cs_insn.bytes.hex() + '\t' + cs_insn.mnemonic + '\t' + cs_insn.op_str
        instruction = Instruction(insn_str)
        instruction.address = cs_insn.address
        basic_block.insert_instruction(instruction)

        if cs_insn.id == ARM64_INS_BL or cs_insn.id == ARM64_INS_BLR:  # 函数调用
            operand = cs_insn.operands[0]  # 获得调用的值
            if operand.type != ARM64_OP_IMM:
                print('The operand type is not IMM')
            try:
                _function = mach_info.functions[hex(operand.imm)]  # 取得调用的函数
            except Exception as e:
                continue

            # 解析出函数名
            function_name = mach_info.symbols[hex(_function)]

            if function_name == "_objc_msgSendSuper2":  # 调用父类方法
                handle_super_method(mach_info, class_data, inter, instruction)
                # basic_block.insert_instruction(instruction)

            elif function_name == "_objc_storeStrong":  # 一些特殊方法
                reg0_value = inter.gen_regs[0].value
                reg1_value = inter.gen_regs[1].value
                inter.modify_memory(reg0_value, reg1_value)

            elif function_name == "_objc_msgSend":  # 调用方法
                # 处理普通方法调用
                result = handle_method_call(mach_info, class_data, class_name, method_name, inter, method_hub, instruction, recurive_stack=r_stack)
                # if result:
                #     basic_block.insert_instruction(instruction)
            else:
                result = handle_method_call(mach_info, class_data, class_name, method_name, inter, method_hub, instruction, recursive_stack, False, function_name)
                filtered_functions = {'_objc_msgSendSuper2', '_objc_storeStrong', '_objc_msgSend',
                                      '_objc_retainAutoreleasedReturnValue', '_objc_release'}
                # if result and function_name not in filtered_functions:
                #     basic_block.insert_instruction(instruction)

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
            basic_block.is_return = True
            return basic_block
    return basic_block


def _analyse_method(method, mach_info, method_hub=None, recursive=True, recursive_stack=set([])):

    r_stack = recursive_stack.copy()

    def memory_provider(address):
        if address < 0x1000:  # 因为小于 0x1000 不会是地址，当时是为了 ivar
            return address
        try:
            result, content = mach_info.get_memory_content(address, 8)
            if result:
                return content
            else:
                if hex(address) in mach_info.symbols:
                    return address
                return content
        except Exception as _:
            return 0

    def store_notify(memory, value):
        if memory in mach_info.statics:
            type_name = get_obj_name(mach_info, value, class_name, class_data)
            static_name = mach_info.statics[memory]
            mach_info.statics_class[hex(static_name)] = type_name

    method_address_key = hex(method[0].address)
    if method_address_key in mach_info.methods:  # pass the functions
        class_name, method_name = mach_info.methods[method_address_key]
    elif method_address_key in mach_info.functions:
        class_name = '$Function'
        method_name = mach_info.symbols[hex(mach_info.functions[method_address_key])]
    else:
        return None

    # 参数等会儿考虑
    if class_name == '$Function':
        arguments_count = 8  # 如果是函数，假设共有 8 个参数
        arguments = []
    elif class_name == '$Block':
        arguments = []
    else:
        method_arguments = mach_info.get_arguments_from_method(class_name, method_name)
        # 传入解释器的参数类型（float, int）
        # 传入解释器的参数(type, length, value)
        arguments = [('int', 8, SELF_POINTER), ('int', 8, CURRENT_SELECTOR)]
        if len(method_arguments) > 2:
            for i in range(2, len(method_arguments)):
                argument_type = method_arguments[i].type
                length = method_arguments[i].length
                argument = None
                if argument_type == 'id' or argument_type == 'Class' or argument_type == 'SEL' or argument_type == 'Pointer':
                    argument = ('int', length, SELF_POINTER - i + 1)
                elif argument_type == 'Float':
                    argument = ('float', length, SELF_POINTER - i + 1)
                elif argument_type == 'Char' or argument_type == 'Integer' or argument_type == 'Bool':
                    argument = ('int', length, SELF_POINTER - i + 1)
                if argument is not None:
                    arguments.append(argument)

    method_instructions = method_hub.get_method_insn(class_name, method_name)
    if method_instructions is not None:
        return method_instructions

    # 构造一个解释器
    ctx = ExecuteContext()  # 构造一个上下文
    inter = Interpreter(memory_provider=memory_provider, context=ctx, store_notify=store_notify, parameters=arguments)
    print('Current analyse <%s: %s>' % (class_name, method_name))
    r_stack.add((class_name, method_name))

    class_data = None
    if class_name in mach_info.class_name_address:
        data_address = mach_info.class_name_address[class_name]
        class_data = mach_info.class_datas[hex(data_address)]

    # 用来代表当前方法
    method_instructions = MethodInstructions(class_name, method_name)

    # 将当前方法拆分成基本块 basic_blocks_address, basic_blocks
    basic_blocks_keys, basic_blocks_instructions = _slice_basic_block(method)

    method_address_range = (method[0].address, method[-1].address)
    # 判断可达的块
    reachable_blocks_queue = _analyse_reachable_of_basic_blocks(basic_blocks_keys, basic_blocks_instructions, method_address_range)

    blocks_instructions_queue = []  # 执行队列
    basic_block_key = basic_blocks_keys[0]
    blocks_instructions_queue.append(basic_blocks_instructions[basic_block_key])  # 将入口块入队列

    blocks_instructions_index_queue = [0]

    wait_for_follow_queue = []  # 等待分析后续基本块的当前基本块队列
    wait_for_follow_count_queue = []  # 等待分析后续基本块的数量队列

    wait_for_follow = None
    wait_for_follow_count = 0

    return_types = []
    while len(blocks_instructions_queue) > 0:  # 执行队列不为空

        follow_count = 0

        # 设置前向 block
        if wait_for_follow is None and len(wait_for_follow_queue) > 0:
            wait_for_follow = wait_for_follow_queue[0]
            wait_for_follow_queue = wait_for_follow_queue[1:]
            wait_for_follow_count = wait_for_follow_count_queue[0]
            wait_for_follow_count_queue = wait_for_follow_count_queue[1:]

        block_instructions = blocks_instructions_queue[0]  # 队尾出队
        blocks_instructions_queue = blocks_instructions_queue[1:]

        block_instructions_index = blocks_instructions_index_queue[0]
        blocks_instructions_index_queue = blocks_instructions_index_queue[1:]

        if wait_for_follow is not None:
            # 恢复寄存器状态
            inter.restore_state(wait_for_follow.identify)
            wait_for_follow_count -= 1

            if wait_for_follow_count == 0:
                wait_for_follow = None

        if hex(block_instructions[0].address) in method_instructions.all_blocks:  # 如果这个块被执行过了
            continue

        # 模拟执行这个基本块
        block = _analyse_basic_block(block_instructions, hex(block_instructions[0].address),
                                     mach_info, class_data, class_name, method_name, inter, (method[0].address, method[-1].address), method_hub, r_stack)
        method_instructions.all_blocks[block.identify] = block
        # 执行完毕，获取其后续块（跳转过去的块或者下一个块）
        if not block.is_return and (block.jump_to_block is None or
                                   (block.jump_to_block is not None and block.jump_condition is not None)):
            current_index = block_instructions_index
            if current_index + 1 < len(basic_blocks_keys):
                next_block_address_key = basic_blocks_keys[current_index + 1]
                if int(next_block_address_key, 16) in reachable_blocks_queue:  # 只有在该块可达的时候才有必要归入 next_block
                    next_block_instructions = basic_blocks_instructions[next_block_address_key]
                    blocks_instructions_queue.append(next_block_instructions)  # 入队列
                    blocks_instructions_index_queue.append(current_index + 1)
                    follow_count += 1

                    block.next_block = next_block_address_key
        if block.jump_to_block is not None and block.jump_to_block in basic_blocks_instructions:
            jump_to_block_instructions = basic_blocks_instructions[block.jump_to_block]
            blocks_instructions_queue.append(jump_to_block_instructions)  # 入队列
            blocks_instructions_index_queue.append(basic_blocks_keys.index(block.jump_to_block))
            follow_count += 1
        if follow_count > 0:  # 这个块有后续的块
            wait_for_follow_queue.append(block)
            wait_for_follow_count_queue.append(follow_count)
            inter.save_state(block.identify)  # 保存此时的寄存器状态
        else:
            # 在这里获取返回值
            return_value = inter.gen_regs[0].value  # 对象的返回值肯定是存在 r0 寄存器里的
            return_types.append(return_value)

        # 如果入口块是空的，添加入口块
        if method_instructions.entry_block is None:
            method_instructions.entry_block = block

    return_types = list(set(return_types))
    return_types_str = []

    for rt in return_types:

        return_type = get_obj_name(mach_info, rt, class_name, class_data)
        return_types_str.append(return_type)
    method_instructions.return_type = return_types_str
    method_hub.insert_method_insn(method_instructions)
    # print(method_name)
    # for var in ctx.data_flow:
    #     for from_item, to_item, position in ctx.data_flow[var]:
    #         cls, mtd = to_item.goto_insns
    #         to_str = cls + ': ' + mtd
    #         if type(from_item) == str:
    #             print('\t%s -> (%s %d)' % (from_item, to_str, position))
    #         else:
    #             cls, mtd = from_item.goto_insns
    #             from_str = cls + ': ' + mtd
    #             print('\t%s -> (%s %d)' % (from_str, to_str, position))

    for data_var in ctx.data_flow:
        for from_item, to_item, position in ctx.data_flow[data_var]:
            if type(from_item) == str:
                method_instructions.add_data_flow_from_parameter(from_item, to_item, position)
            else:
                method_instructions.add_data_flow_from_instruction(from_item, to_item, position)

    # print(ctx.variable_from)
    # print(ctx.register_variable)
    # print(ctx.memory_variable)
    return method_instructions


# 0 means 64-bit
# 1 means 32-bit
# 2 means both
# Note: if only one arch, just analysis that arch
def static_analysis(binary_file, app_name, arch=0):

    global _g_current_context

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
        _g_current_context = (arch, mode)

        slice_addresses = list(mach_info.methods.keys())
        slice_addresses += list(mach_info.functions.keys())

        sorted_slice_addresses = sorted_list_for_hex_string(slice_addresses)

        # print("Start disassemble all methods!")
        method_hub = MachoMethodHub()  # 对于每一个架构都有一个
        # methods_hubs.append(method_hub)
        # method_instructions = _slice_by_function_for_arm64(arch, mode, mach_info.text, mach_info.text_addr, sorted_slice_addresses, method_hub=method_hub)
        # print("Disassemble complete!")
        # for method_instruction in method_instructions:
        #     _analyse_method(method_instruction, mach_info, method_hub=method_hub)

        pasted_method = check_has_paste_board(method_hub)
        storage_method = check_storage_type(method_hub)
        background_behaviours = check_enter_background(method_hub)
        possible_hot_fix_method = check_possible_hot_fix(method_hub)
        keychain_method = check_access_keychain(method_hub)

        # method_hub.list_all_methods()

        # address = mach_info.get_method_address('ABKModelManager', 'manager')
        # address = mach_info.get_method_address('ABKTipView', 'showWarningWithText:toView:withDuration:')
        # address = mach_info.get_method_address('ABKTipView', 'showText:toView:')
        address = mach_info.get_method_address('ABKTipView', 'showText:toView:')
        m = _disasm_specified_function(arch, mode, mach_info.text, address, mach_info.text_addr, sorted_slice_addresses)
        method_instruction = _analyse_method(m, mach_info, method_hub=method_hub)
        for from_item in method_instruction.data_flows:
            data_flow: MethodDataFlow = method_instruction.data_flows[from_item]
            data_flow.describe()

        # def cfg_provider(class_name, imp_name):
        #     method_instruction = method_hub.get_method_insn(class_name, imp_name)
        #     return method_instruction
        # cfg = generate_cfg(method_instruction, cfg_provider, False)
        # cfg.view()

        # method_ins = method_hub.get_method_insn('AppDelegate', 'application:didFinishLaunchingWithOptions:')
        # method_ins = method_hub.get_method_insn('ABKModelManager', 'queryItemsFromSQLiteWithConditions:ordered:orderKey:')
        # method_ins = method_hub.get_method_insn('ABKModelManager', 'queryItemsFromSQLiteWithStatements:')

        # if method_ins is not None:
        #     cfg = generate_cfg(method_ins, cfg_provider, False)
        #     cfg.view()

        (read_paste_board_path, write_paste_board_path,
         ud_storage_path, ka_storage_path, s_storage_path, c_storage_path,
         i_hotfix_path, s_hotfix_path, e_hotfix_path,
         add_keychain_path, delete_keychain_path, update_keychain_path, select_keychain_path,
         background_path,
         poster_notification_path, handler_notification_path) = setup_output_environment(app_name)

        # print('')
        # # Output the result of analysis
        # print('===================================================')
        # # Output the method read or write paste board
        # read_paste_method = pasted_method['read_paste_board']
        # write_paste_method = pasted_method['write_paste_board']
        # print('Follow methods has read the content from paste board:')
        # for cls, method in read_paste_method:
        #
        # #     if method_ins is not None:
        # #         cfg = generate_cfg(method_ins, cfg_provider, True)
        # #         cfg.save_to(read_paste_board_path)
        #     print('\t', cls, method)
        #     method_ins = method_hub.get_method_insn(cls, method)
        #     # for from_item in method_ins.data_flows:
        #     #     data_flow: MethodDataFlow = method_ins.data_flows[from_item]
        #     #     data_flow.describe()
        # print('')
        # print('Follow methods has write the content to paste board:')
        # for cls, method in write_paste_method:
        #     # method_ins = method_hub.get_method_insn(cls, method)
        #     # if method_ins is not None:
        #     #     cfg = generate_cfg(method_ins, cfg_provider, True)
        #     #     cfg.save_to(write_paste_board_path)
        #     print('\t', cls, method)
        # print('')
        #
        # print('===================================================')
        # # Output the method storage
        # print('Follow methods using `UserDefaults` to store data:')
        # for cls, method in storage_method['user_defaults']:
        #     # method_ins = method_hub.get_method_insn(cls, method)
        #     # if method_ins is not None:
        #     #     cfg = generate_cfg(method_ins, cfg_provider, True)
        #     #     cfg.save_to(ud_storage_path)
        #     print('\t', cls, method)
        # print('')
        # print('Follow methods using `KeyArchived` to store data:')
        # for cls, method in storage_method['key_archived']:
        #     # method_ins = method_hub.get_method_insn(cls, method)
        # #     if method_ins is not None:
        # #         cfg = generate_cfg(method_ins, cfg_provider, True)
        # #         cfg.save_to(ka_storage_path)
        #     print('\t', cls, method)
        # print('')
        # print('Follow methods using `SQLite` to store data:')
        # for cls, method in storage_method['sqlite']:
        # #     method_ins = method_hub.get_method_insn(cls, method)
        # #     if method_ins is not None:
        # #         cfg = generate_cfg(method_ins, cfg_provider, True)
        # #         cfg.save_to(s_storage_path)
        #     print('\t', cls, method)
        # print('')
        # print('Follow methods using `Core Data` to store data:')
        # for cls, method in storage_method['coredata']:
        # #     method_ins = method_hub.get_method_insn(cls, method)
        # #     if method_ins is not None:
        # #         cfg = generate_cfg(method_ins, cfg_provider, True)
        # #         cfg.save_to(c_storage_path)
        #     print('\t', cls, method)
        # print('')
        #
        # print('===================================================')
        # # Output the method hotfix
        # print('Follow methods call the `JSContext` method, maybe using `hotfix`:')
        # print('* init JSContext:')
        # for cls, method in possible_hot_fix_method['js_context_init']:
        # #     method_ins = method_hub.get_method_insn(cls, method)
        # #     if method_ins is not None:
        # #         cfg = generate_cfg(method_ins, cfg_provider, True)
        # #         cfg.save_to(i_hotfix_path)
        #     print('\t', cls, method)
        # print('* set `OC` behaviour to JSContext: (The detail of behaviour cannot find out currently)')
        # for cls, method in possible_hot_fix_method['js_context_set']:
        # #     method_ins = method_hub.get_method_insn(cls, method)
        # #     if method_ins is not None:
        # #         cfg = generate_cfg(method_ins, cfg_provider, True)
        # #         cfg.save_to(s_hotfix_path)
        #     print('\t', cls, method)
        # print('* evaluate JSContext:')
        # for cls, method in possible_hot_fix_method['js_context_evaluate']:
        # #     method_ins = method_hub.get_method_insn(cls, method)
        # #     if method_ins is not None:
        # #         cfg = generate_cfg(method_ins, cfg_provider, True)
        # #         cfg.save_to(e_hotfix_path)
        #     print('\t', cls, method)
        # print('')
        #
        # print('===================================================')
        # # Output the method keychain
        # print('Follow methods has added data to keychain:')
        # for cls, method in keychain_method['add_keychain']:
        # #     method_ins = method_hub.get_method_insn(cls, method)
        # #     if method_ins is not None:
        # #         cfg = generate_cfg(method_ins, cfg_provider, True)
        # #         cfg.save_to(add_keychain_path)
        #     print('\t', cls, method)
        # print('')
        # print('Follow methods has searched data from keychain:')
        # for cls, method in keychain_method['search_keychain']:
        # #     method_ins = method_hub.get_method_insn(cls, method)
        # #     if method_ins is not None:
        # #         cfg = generate_cfg(method_ins, cfg_provider, True)
        # #         cfg.save_to(select_keychain_path)
        #     print('\t', cls, method)
        # print('')
        # print('Follow methods has updated data to keychain:')
        # for cls, method in keychain_method['update_keychain']:
        # #     method_ins = method_hub.get_method_insn(cls, method)
        # #     if method_ins is not None:
        # #         cfg = generate_cfg(method_ins, cfg_provider, True)
        # #         cfg.save_to(update_keychain_path)
        #     print('\t', cls, method)
        # print('')
        # print('Follow methods has deleted data from keychain:')
        # for cls, method in keychain_method['delete_keychain']:
        # #     method_ins = method_hub.get_method_insn(cls, method)
        # #     if method_ins is not None:
        # #         cfg = generate_cfg(method_ins, cfg_provider, True)
        # #         cfg.save_to(delete_keychain_path)
        #     print('\t', cls, method)
        # print('')
        #
        # print('===================================================')
        # # Output the background behaviour
        # print('Follow methods are the behaviours when the application did/will enter background:')
        # behaviours = background_behaviours['background_behaviours']
        # for key in behaviours:
        #     if len(behaviours[key]) > 0:
        #         cls, method = key
        # #         method_ins = method_hub.get_method_insn(cls, method)
        # #         if method_ins is not None:
        # #             cfg = generate_cfg(method_ins, cfg_provider, True)
        # #             cfg.save_to(background_path)
        #         print('* In method `%s` of class `%s`' % (cls, method))
        #         for api_cls, api_method in behaviours[key]:
        #             print('\t', api_cls, api_method)
        # print('')
        #
        # print('===================================================')
        # # Output the notification
        # print('Follow methods post notification:')
        # for notification in mach_info.notification_poster:
        #     print('* %s' % notification)
        #     for cls, method in mach_info.notification_poster[notification]:
        # #         method_ins = method_hub.get_method_insn(cls, method)
        # #         if method_ins is not None:
        # #             cfg = generate_cfg(method_ins, cfg_provider, True)
        # #             cfg.save_to(poster_notification_path)
        #         print('\t', cls, method)
        # print('')
        #
        # print('Follow methods handle notification:')
        # for notification in mach_info.notification_handler:
        #     print('* %s' % notification)
        #     for cls, method in mach_info.notification_handler[notification]:
        # #         method_ins = method_hub.get_method_insn(cls, method)
        # #         if method_ins is not None:
        # #             cfg = generate_cfg(method_ins, cfg_provider, True)
        # #             cfg.save_to(handler_notification_path)
        #         print('\t', cls, method)

    mach_o_file.close()


def setup_output_environment(app_name):
    if not os.path.exists('cfgs'):
        os.mkdir('cfgs')

    if os.path.exists('cfgs/' + app_name):
        shutil.rmtree('cfgs/' + app_name)

    cfg_path = 'cfgs/' + app_name

    os.mkdir(cfg_path)
    os.mkdir(cfg_path + '/paste_board')
    read_paste_board_path = cfg_path + '/paste_board/read'
    os.mkdir(read_paste_board_path)
    write_paste_board_path = cfg_path + '/paste_board/write'
    os.mkdir(write_paste_board_path)

    os.mkdir(cfg_path + '/storage')
    ud_storage_path = cfg_path + '/storage/user_defaults'
    os.mkdir(ud_storage_path)
    ka_storage_path = cfg_path + '/storage/key_archived'
    os.mkdir(ka_storage_path)
    s_storage_path = cfg_path + '/storage/sqlite'
    os.mkdir(s_storage_path)
    c_storage_path = cfg_path + '/storage/coredata'
    os.mkdir(c_storage_path)

    os.mkdir(cfg_path + '/hotfix')
    i_hotfix_path = cfg_path + '/hotfix/init'
    os.mkdir(i_hotfix_path)
    s_hotfix_path = cfg_path + '/hotfix/set'
    os.mkdir(s_hotfix_path)
    e_hotfix_path = cfg_path + '/hotfix/evaluate'
    os.mkdir(e_hotfix_path)

    os.mkdir(cfg_path + '/keychain')
    add_keychain_path = cfg_path + '/keychain/add'
    os.mkdir(add_keychain_path)
    delete_keychain_path = cfg_path + '/keychain/delete'
    os.mkdir(delete_keychain_path)
    update_keychain_path = cfg_path + '/keychain/update'
    os.mkdir(update_keychain_path)
    select_keychain_path = cfg_path + '/keychain/select'
    os.mkdir(select_keychain_path)

    background_path = cfg_path + '/background'
    os.mkdir(background_path)

    os.mkdir(cfg_path + '/notification')
    poster_notification_path = cfg_path + '/notification/poster'
    os.mkdir(poster_notification_path)
    handler_notification_path = cfg_path + '/notification/handler'
    os.mkdir(handler_notification_path)

    return (read_paste_board_path, write_paste_board_path,
            ud_storage_path, ka_storage_path, s_storage_path, c_storage_path,
            i_hotfix_path, s_hotfix_path, e_hotfix_path,
            add_keychain_path, delete_keychain_path, update_keychain_path, select_keychain_path,
            background_path,
            poster_notification_path, handler_notification_path)

# Reference:
# > https://zhuanlan.zhihu.com/p/24858664
