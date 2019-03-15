from models.macho_method_hub import *


def _check_storage_type(method, method_hub, method_cache, recursive_set=set([])):
    recursive_set.add(method)

    k_user_defaults = 0
    k_keyed_archive = 0
    k_sqlite = 0
    k_core_data = 0

    user_defaults_method = {
        'standardUserDefaults',
        'init',
        'initWithSuiteName:',
        'setObject:forKey:',
        'setFloat:forKey:',
        'setDouble:forKey:',
        'setInteger:forKey:',
        'setBool:forKey:',
        'setURL:forKey:',
        'removeObjectForKey:',
        'objectForKey:',
        'stringForKey:',
        'URLForKey:',
        'arrayForKey:',
        'dictionaryForKey:',
        'stringArrayForKey:',
        'dataForKey:',
        'boolForKey:',
        'integerForKey:',
        'floatForKey:',
        'doubleForKey:',
        'dictionaryRepresentation'
    }

    keyed_archive_method = {
        'archivedDataWithRootObject:',
        'archiveRootObject:toFile:',
        'archivedDataWithRootObject:requiringSecureCoding:error:',
        'encodeBool:forKey:',
        'encodeBytes:length:forKey:',
        'encodeConditionalObject:forKey:',
        'encodeDouble:forKey:',
        'encodeFloat:forKey:',
        'encodeInt:forKey:',
        'encodeInt32:forKey:',
        'encodeInt64:forKey:',
        'encodeObject:forKey:',
        'unarchiveObjectWithData:',
        'unarchiveObjectWithFile:',
        'containsValueForKey:',
        'decodeBollForKey:',
        'decodeBytesForKey:returnedLength:',
        'decodeDoubleForKey:',
        'decodeFloatForKey:',
        'decodeIntForKey:',
        'decodeInt32ForKey:',
        'decodeInt64ForKey:',
        'decodeObjectForKey:',
        'unarchivedObjectOfClass:fromData:error:',
        'unarchivedObjectOfClasses:fromData:error:'
    }

    # 分析某个方法有没有调用数据存储方法
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
                    u, k, s, c = class_method_cache[method_name]
                    k_user_defaults |= u
                    k_keyed_archive |= k
                    k_sqlite |= s
                    k_core_data |= c
                else:
                    if called_method in recursive_set:
                        continue
                    else:
                        u, k, s, c = _check_storage_type(called_method, method_hub, method_cache, recursive_set.copy())
                        k_user_defaults |= u
                        k_keyed_archive |= k
                        k_sqlite |= s
                        k_core_data |= c
                        if class_name not in method_cache:
                            method_cache[class_name] = {}
                        method_cache[class_name][method_name] = (u, k, s, c)
            else:
                if class_name == 'NSUserDefaults' and method_name in user_defaults_method:
                    k_user_defaults = 1
                if ((class_name == 'NSKeyedArchiver' or class_name == 'NSKeyedUnarchiver') and
                    method_name in keyed_archive_method):
                    k_keyed_archive = 1

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

    return k_user_defaults, k_keyed_archive, k_sqlite, k_core_data


def check_storage_type(method_hub):
    print('Start checking storage type...')

    user_defaults = []
    key_archived = []
    sqllite = []
    coredata = []

    method_cache = {}  # 使用 dict 存储结果 {class : {method_name: (0, 0, 0, 0)}}

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
                u, k, s, c = _check_storage_type(method, method_hub, method_cache)
                if class_key not in method_cache:
                    method_cache[class_key] = {}
                method_cache[class_key][method.method_name] = (u, k, s, c)
                if u == 1:
                    user_defaults.append((method.class_name, method.method_name))
                if k == 1:
                    key_archived.append((method.class_name, method.method_name))
                if s == 1:
                    sqllite.append((method.class_name, method.method_name))
                if c == 1:
                    coredata.append((method.class_name, method.method_name))

    print('Checking finish!')

    result = {
        'user_defaults': user_defaults,
        'key_archived': key_archived,
        'sqlite': sqllite,
        'coredata': coredata
    }
    return result
