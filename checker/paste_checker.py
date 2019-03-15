from models.macho_method_hub import *


def _check_has_paste_board_for_method(method, method_hub, method_cache, recursive_set=set([])):

    recursive_set.add(method)

    k_general_paste_board_create = 0  # 创建剪切板
    k_general_paste_board_read = 0    # 从剪切板中读内容
    k_general_paste_board_write = 0   # 向剪切板中写内容

    paste_board_read_methods = {
        'dataForPasteboardType:',
        'valueForPasteboardType:',
        'itemSetWithPasteboardTypes:',
        'valuesForPasteboardType:inItemSet:',
        'dataForPasteboardType:inItemSet:',
        'string', 'strings',
        'URL', 'URLs',
        'image', 'images',
        'color', 'colors'
    }
    paste_board_write_methods = {
        'setValue:forPasteboardType:',
        'setData:forPasteboardType:',
        'addItems:',
        'setString:', 'setStrings:',
        'setURL:', 'setURLs:',
        'setImage:', 'setImages:',
        'setColor:', 'setColors:'
    }

    # 分析某个方法有没有调用剪切板相关方法
    entry_block = method.entry_block
    wait_for_check_block = [entry_block]
    analysed_block = set([])

    while len(wait_for_check_block) > 0:  # 队列中还有
        block = wait_for_check_block[0]
        wait_for_check_block = wait_for_check_block[1:]

        if block.identify in analysed_block:
            continue

        for instruction in block.instructions:
            class_name, method_name = instruction.goto_insns
            class_method_cache = None
            if class_name in method_cache:
                class_method_cache = method_cache[class_name]

            # print('\tgoto:', class_name, method_name)
            called_method = method_hub.get_method_insn(class_name, method_name)
            if called_method is not None:
                if class_method_cache is not None and method_name in class_method_cache:  # Already
                    c, r, w = class_method_cache[method_name]
                    k_general_paste_board_create |= c
                    k_general_paste_board_read |= r
                    k_general_paste_board_write |= w
                else:
                    if called_method in recursive_set:
                        continue
                    else:
                        c, r, w = _check_has_paste_board_for_method(called_method, method_hub, method_cache, recursive_set.copy())
                        k_general_paste_board_create |= c
                        k_general_paste_board_read |= r
                        k_general_paste_board_write |= w
                        if class_name not in method_cache:
                            method_cache[class_name] = {}
                        method_cache[class_name][method_name] = (c, r, w)
            else:
                if class_name == 'UIPasteboard':
                    if method_name == 'generalPasteboard':
                        k_general_paste_board_create = 1
                    elif method_name in paste_board_read_methods:
                        k_general_paste_board_read = 1
                    elif method_name in paste_board_write_methods:
                        k_general_paste_board_write = 1

        analysed_block.add(block.identify)

        # 分析后续块
        if not block.is_return:
            if block.jump_to_block is not None:
                if block.jump_condition is not None:  # 有条件跳转
                    # next
                    next_block = method.all_blocks[block.next_block]
                    if next_block.identify not in analysed_block:
                        wait_for_check_block.append(next_block)
                # jump
                if block.jump_to_block in method.all_blocks:
                    jump_block = method.all_blocks[block.jump_to_block]
                    if jump_block.identify not in analysed_block:
                        wait_for_check_block.append(jump_block)
            else:
                # next
                if block.next_block is not None:
                    next_block = method.all_blocks[block.next_block]
                    if next_block.identify not in analysed_block:
                        wait_for_check_block.append(next_block)

    return k_general_paste_board_create, k_general_paste_board_read, k_general_paste_board_write


def check_has_paste_board(method_hub):

    print('Start checking if has visited paste board...')
    read_methods = []
    write_methods = []
    method_cache = {}  # 使用 dict 存储结果 {class : {method_name: (0, 0, 0)}}

    for class_key in method_hub.method_insns:  # 这样遍历字典速度比较快
        # print('===================', class_key, '===================')

        class_method_cache = None
        if class_key in method_cache:
            class_method_cache = method_cache[class_key]

        class_methods = method_hub.method_insns[class_key]
        for method in class_methods:  # 遍历这个类的所有方法
            if class_method_cache is not None and method.method_name in class_method_cache:  # 这个方法之前分析过了
                continue
            else:
                c, r, w = _check_has_paste_board_for_method(method, method_hub, method_cache)
                if class_key not in method_cache:
                    method_cache[class_key] = {}
                method_cache[class_key][method.method_name] = (c, r, w)
                if c == 1 and r == 1:
                    read_methods.append((method.class_name, method.method_name))
                if c == 1 and w == 1:
                    write_methods.append((method.class_name, method.method_name))

    print('Checking finish!')

    result = {
        'read_paste_board': read_methods,
        'write_paste_board': write_methods
    }
    return result
