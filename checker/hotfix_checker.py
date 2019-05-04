from models.macho_method_hub import *


def _check_possible_hot_fix_for_method(method, method_hub, method_cache, recursive_set=set([]), verbose=False):

    recursive_set.add(method)

    k_js_context_init = 0
    k_js_context_set = 0
    k_js_context_evaluate = 0

    js_context_init_methods = {
        'alloc', 'init',
        'initWithVirtualMachine:'
    }

    js_context_set_methods = {
        'setObject:forKeyedSubscript:'
    }

    js_context_evaluate_methods = {
        'evaluateScript:',
        'evaluateScript:withSourceURL:'
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
            if instruction.goto_insns is None:
                continue
            class_name, method_name = instruction.goto_insns
            class_method_cache = None
            if class_name in method_cache:
                class_method_cache = method_cache[class_name]

            if verbose:
                print('\tgoto:', class_name, method_name)
            called_method = method_hub.get_method_insn(class_name, method_name)
            if called_method is not None:
                if class_method_cache is not None and method_name in class_method_cache:  # Already
                    i, s, e = class_method_cache[method_name]
                    k_js_context_init |= i
                    k_js_context_set |= s
                    k_js_context_evaluate |= e
                else:
                    if called_method in recursive_set:
                        continue
                    else:
                        i, s, e = _check_possible_hot_fix_for_method(called_method, method_hub, method_cache, recursive_set.copy(), verbose)
                        k_js_context_init |= i
                        k_js_context_set |= s
                        k_js_context_evaluate |= e
                        if class_name not in method_cache:
                            method_cache[class_name] = {}
                        method_cache[class_name][method_name] = (i, s, e)
            else:
                if class_name == 'JSContext':
                    if method_name in js_context_init_methods:
                        k_js_context_init = 1
                    elif method_name in js_context_set_methods:
                        k_js_context_set = 1
                    elif method_name in js_context_evaluate_methods:
                        k_js_context_evaluate = 1

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

    return k_js_context_init, k_js_context_set, k_js_context_evaluate


def check_possible_hot_fix(method_hub, verbose=False):
    print('Start checking possible hot fix...')

    context_init = []
    context_set = []
    context_evaluate = []

    method_cache = {}  # 使用 dict 存储结果 {class : {method_name: (0, 0, 0)}}

    for class_key in method_hub.method_insns:  # 这样遍历字典速度比较快
        if verbose:
            print(class_key + ':')

        class_method_cache = None
        if class_key in method_cache:
            class_method_cache = method_cache[class_key]

        class_methods = method_hub.method_insns[class_key]
        for method in class_methods:  # 遍历这个类的所有方法
            if class_method_cache is not None and method.method_name in class_method_cache:  # 这个方法之前分析过了
                continue
            else:
                i, s, e = _check_possible_hot_fix_for_method(method, method_hub, method_cache, verbose=verbose)
                if class_key not in method_cache:
                    method_cache[class_key] = {}
                method_cache[class_key][method.method_name] = (i, s, e)
                if i == 1:
                    context_init.append((method.class_name, method.method_name))
                if s == 1:
                    context_set.append((method.class_name, method.method_name))
                if e == 1:
                    context_evaluate.append((method.class_name, method.method_name))

    print('Checking finish!')

    result = {
        'js_context_init': context_init,
        'js_context_set': context_set,
        'js_context_evaluate': context_evaluate
    }
    return result
