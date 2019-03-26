from models.macho_method_hub import *


def _check_access_keychain_for_method(method, method_hub, method_cache, recursive_set=set([])):

    recursive_set.add(method)

    k_keychain_add = 0
    k_keychain_search = 0
    k_keychain_update = 0
    k_keychain_delete = 0

    keychain_add_functions = {
        'SecItemAdd'
    }

    keychain_search_functions = {
        '_SecItemCopyMatching'
    }

    keychain_update_functions = {
        '_SecItemUpdate'
    }

    keychain_delete_functions = {
        '_SecItemDelete'
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

            print('\tgoto:', class_name, method_name)
            called_method = method_hub.get_method_insn(class_name, method_name)
            if called_method is not None:
                if class_method_cache is not None and method_name in class_method_cache:  # Already
                    a, s, u, d = class_method_cache[method_name]
                    k_keychain_add |= a
                    k_keychain_search |= s
                    k_keychain_update |= u
                    k_keychain_delete |= d
                else:
                    if called_method in recursive_set:
                        continue
                    else:
                        a, s, u, d = _check_access_keychain_for_method(called_method, method_hub, method_cache, recursive_set.copy())
                        k_keychain_add |= a
                        k_keychain_search |= s
                        k_keychain_update |= u
                        k_keychain_delete |= d
                        if class_name not in method_cache:
                            method_cache[class_name] = {}
                        method_cache[class_name][method_name] = (a, s, u, d)
            else:
                if method_name in keychain_add_functions:
                    k_keychain_add = 1
                elif method_name in keychain_search_functions:
                    k_keychain_search = 1
                elif method_name in keychain_update_functions:
                    k_keychain_update = 1
                elif method_name in keychain_delete_functions:
                    k_keychain_delete = 1

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

    return k_keychain_add, k_keychain_search, k_keychain_update, k_keychain_delete


def check_access_keychain(method_hub):
    print('Start checking access keychain...')

    keychain_add = []
    keychain_search = []
    keychain_update = []
    keychain_delete = []

    method_cache = {}  # 使用 dict 存储结果 {class : {method_name: (0, 0, 0, 0)}}

    for class_key in method_hub.method_insns:  # 这样遍历字典速度比较快
        print(class_key + ':')

        class_method_cache = None
        if class_key in method_cache:
            class_method_cache = method_cache[class_key]

        class_methods = method_hub.method_insns[class_key]
        for method in class_methods:  # 遍历这个类的所有方法
            if class_method_cache is not None and method.method_name in class_method_cache:  # 这个方法之前分析过了
                continue
            else:
                a, s, u, d = _check_access_keychain_for_method(method, method_hub, method_cache)
                if class_key not in method_cache:
                    method_cache[class_key] = {}
                method_cache[class_key][method.method_name] = (a, s, u, d)
                if a == 1:
                    keychain_add.append((method.class_name, method.method_name))
                if s == 1:
                    keychain_search.append((method.class_name, method.method_name))
                if u == 1:
                    keychain_update.append((method.class_name, method.method_name))
                if d == 1:
                    keychain_delete.append((method.class_name, method.method_name))

    print('Checking finish!')

    result = {
        'add_keychain': keychain_add,
        'search_keychain': keychain_search,
        'update_keychain': keychain_update,
        'delete_keychain': keychain_delete
    }
    return result
