from models.macho_method_hub import *


def _check_enter_background_for_method(method, method_hub, method_cache, recursive_set=set([])):

    recursive_set.add(method)

    # 分析某个方法有没有调用剪切板相关方法
    entry_block = method.entry_block
    wait_for_check_block = [entry_block]
    analysed_block = set([])

    called_apis = []

    while len(wait_for_check_block) > 0:  # 队列中还有
        block = wait_for_check_block[0]
        wait_for_check_block = wait_for_check_block[1:]

        if block.identify in analysed_block:
            continue

        for instruction in block.instructions:
            if instruction.goto_insns is None:
                continue
            class_name, method_name = instruction.goto_insns
            class_method_cache = None
            if class_name in method_cache:
                class_method_cache = method_cache[class_name]

            print('\tgoto:', class_name, method_name)
            called_method = method_hub.get_method_insn(class_name, method_name)
            if called_method is not None:
                if class_method_cache is not None and method_name in class_method_cache:  # Already
                    apis = class_method_cache[method_name]
                    called_apis += apis
                else:
                    if called_method in recursive_set:
                        continue
                    else:
                        apis = _check_enter_background_for_method(called_method, method_hub, method_cache, recursive_set.copy())
                        called_apis += apis
                        if class_name not in method_cache:
                            method_cache[class_name] = {}
                        method_cache[class_name][method_name] = apis
            else:
                called_apis.append((class_name, method_name))

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

    return called_apis


def check_enter_background(method_hub):

    print('Start checking enter background behaviour...')

    enter_background_behaviours = {}

    method_cache = {}  # 使用 dict 存储结果 {class : {method_name: (0, 0, 0)}}

    enter_background_methods = {
        'applicationWillResignActive:',
        'applicationDidEnterBackground:'
    }

    for class_key in method_hub.method_insns:  # 这样遍历字典速度比较快
        print(class_key + ':')

        class_method_cache = None
        if class_key in method_cache:
            class_method_cache = method_cache[class_key]

        class_methods = method_hub.method_insns[class_key]
        for method in class_methods:  # 遍历这个类的所有方法
            if method.method_name not in enter_background_methods:  # 过滤掉不是进入后台的方法
                continue
            if class_method_cache is not None and method.method_name in class_method_cache:  # 这个方法之前分析过了
                continue
            else:
                behaviours = _check_enter_background_for_method(method, method_hub, method_cache)
                enter_background_behaviours[(class_key, method.method_name)] = behaviours
                if class_key not in method_cache:
                    method_cache[class_key] = {}
                method_cache[class_key][method.method_name] = behaviours

    print('Checking finish!')

    result = {
        'background_behaviours': enter_background_behaviours
    }
    return result
