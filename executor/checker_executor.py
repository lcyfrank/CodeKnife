_g_result_list = []
_g_mach_info = None
_g_method_hub = None

caller = None
callee = None


def execute_checker(checker_code: str, mach_info, method_hub):
    global _g_result_list
    global _g_mach_info
    global _g_method_hub

    global caller
    global callee

    _g_result_list = []
    _g_mach_info = mach_info
    _g_method_hub = method_hub
    caller = CKCaller()
    callee = CKCallee()

    try:
        code = compile(checker_code, '<string>', 'exec')
    except Exception as e:
        return [{'msg': str(e), 'type': -1}]
    try:
        exec(code)
    except Exception as e:
        _g_result_list.append({'msg': str(e), 'type': -1})
    return _g_result_list.copy()


def ck_log(msg):
    global _g_result_list
    _g_result_list.append({'msg': convert_inner_type(msg), 'type': 0})


class CKCaller:

    def find(self, target: dict):
        global _g_mach_info
        global _g_method_hub

        result_methods = {}
        method_cache = {}
        for class_key in _g_method_hub.method_insns:

            class_method_cache = None
            if class_key in method_cache:
                class_method_cache = class_key

            class_methods = _g_method_hub.method_insns[class_key]
            for method in class_methods:  # 遍历这个类的所有方法
                if class_method_cache is not None and method.method_name in class_method_cache:  # 这个方法之前分析过了
                    continue
                else:
                    result = self._find_for_method(method, target, _g_method_hub, method_cache)
                    if class_key not in method_cache:
                        method_cache[class_key] = {}
                    method_cache[class_key][method.method_name] = result
                    if result:
                        if method.class_name not in result_methods:
                            result_methods[method.class_name] = []
                        result_methods[method.class_name].append(method.method_name)

        return result_methods

    def _find_for_method(self, method, target: dict, method_hub, method_cache, recursive_set=set([])):
        recursive_set.add(method)

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

                called_method = method_hub.get_method_insn(class_name, method_name)
                if called_method is not None:
                    if class_method_cache is not None and method_name in class_method_cache:  # Already
                        if class_method_cache[method_name]:
                            return True
                    else:
                        if called_method in recursive_set:
                            continue
                        else:
                            result = self._find_for_method(called_method, target, method_hub, method_cache, recursive_set.copy())
                            if result:
                                return True
                            if class_name not in method_cache:
                                method_cache[class_name] = {}
                            method_cache[class_name][method_name] = result
                else:
                    if '*' in target:
                        method_names = target['*']
                        result = method_name in method_names or '*' in method_names
                        if result:
                            return True
                    if class_name in target:
                        method_names = target[class_name]
                        result = method_name in method_names or '*' in method_names
                        if result:
                            return True

            analysed_block.add(block.identify)

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

        return False

    def find_function(self, target: list):
        global _g_mach_info
        global _g_method_hub

        result_methods = {}
        method_cache = {}
        for class_key in _g_method_hub.method_insns:

            class_method_cache = None
            if class_key in method_cache:
                class_method_cache = method_cache[class_key]

            class_methods = _g_method_hub.method_insns[class_key]
            for method in class_methods:
                if class_method_cache is not None and method.method_name in class_method_cache:  # 这个方法之前分析过了
                    continue
                else:
                    result = self._find_function_for_method(method, target, _g_method_hub, method_cache)
                    if class_key not in method_cache:
                        method_cache[class_key] = {}
                    method_cache[class_key][method.method_name] = result
                    if result:
                        if method.class_name not in result_methods:
                            result_methods[method.class_name] = []
                        result_methods[method.class_name].append(method.method_name)

        return result_methods

    def _find_function_for_method(self, method, target: list, method_hub, method_cache, recursive_set=set([])):
        recursive_set.add(method)

        entry_block = method.entry_block
        wait_for_check_block = [entry_block]
        analysed_block = set([])

        while len(wait_for_check_block) > 0:
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
                called_method = method_hub.get_method_insn(class_name, method_name)

                if called_method is not None:
                    if class_method_cache is not None and method_name in class_method_cache:
                        if class_method_cache[method_name]:
                            return True
                    else:
                        if called_method in recursive_set:
                            continue
                        else:
                            result = self._find_function_for_method(called_method, target, method_hub, method_cache, recursive_set.copy())
                            if result:
                                return True
                            if class_name not in method_cache:
                                method_cache[class_name] = {}
                            method_cache[class_name][method_name] = result
                else:
                    if method_name in target:
                        return True

            analysed_block.add(block.identify)

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
        return False


class CKCallee:

    def find_api(self, target: dict):
        global _g_mach_info
        global _g_method_hub

        methods_result = {}
        method_cache = {}

        for class_key in _g_method_hub.method_insns:
            class_method_cache = None
            if class_key in method_cache:
                class_method_cache = method_cache[class_key]

            if class_key in target:
                method_names = target[class_key]
                class_methods = _g_method_hub.method_insns[class_key]
                for method in class_methods:
                    if method.method_name not in method_names:
                        continue
                    if class_method_cache is not None and method.method_name in class_method_cache:  # 这个方法之前分析过了
                        continue
                    results = self._find_for_method(method, target, _g_method_hub, method_cache)
                    methods_result['[' + class_key + ' ' + method.method_name + ']'] = results
                    if class_key not in method_cache:
                        method_cache[class_key] = {}
                    method_cache[class_key][method.method_name] = results

            if '*' in target:
                method_names = target['*']
                class_methods = _g_method_hub.method_insns[class_key]
                for method in class_methods:
                    if method.method_name not in method_names:
                        continue
                    if class_method_cache is not None and method.method_name in class_method_cache:
                        continue
                    results = self._find_for_method(method, target, _g_method_hub, method_cache)
                    methods_result['[' + class_key + ' ' + method.method_name + ']'] = results
                    if class_key not in method_cache:
                        method_cache[class_key] = {}
                    method_cache[class_key][method.method_name] = results
        return methods_result

    def _find_for_method(self, method, target: dict, method_hub, method_cache, recursive_set=set([]), api_only=True):
        recursive_set.add(method)

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
                if not api_only:
                    called_apis.append((class_name, method_name))
                    continue

                class_method_cache = None
                if class_name in method_cache:
                    class_method_cache = method_cache[class_name]
                called_method = method_hub.get_method_insn(class_name, method_name)

                if called_method is not None:
                    if class_method_cache is not None and method_name in class_method_cache:  # Already
                        apis = class_method_cache[method_name]
                        called_apis += apis
                    else:
                        if called_method in recursive_set:
                            continue
                        else:
                            apis = self._find_for_method(called_method, target, method_hub, method_cache, recursive_set.copy())
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

    def find(self, target: dict):
        global _g_mach_info
        global _g_method_hub

        methods_result = {}
        method_cache = {}

        for class_key in _g_method_hub.method_insns:
            class_method_cache = None
            if class_key in method_cache:
                class_method_cache = method_cache[class_key]

            if class_key in target:
                method_names = target[class_key]
                class_methods = _g_method_hub.method_insns[class_key]
                for method in class_methods:
                    if method.method_name not in method_names:
                        continue
                    if class_method_cache is not None and method.method_name in class_method_cache:  # 这个方法之前分析过了
                        continue
                    results = self._find_for_method(method, target, _g_method_hub, method_cache, api_only=False)
                    methods_result['[' + class_key + ' ' + method.method_name + ']'] = results
                    if class_key not in method_cache:
                        method_cache[class_key] = {}
                    method_cache[class_key][method.method_name] = results

            if '*' in target:
                method_names = target['*']
                class_methods = _g_method_hub.method_insns[class_key]
                for method in class_methods:
                    if method.method_name not in method_names:
                        continue
                    if class_method_cache is not None and method.method_name in class_method_cache:
                        continue
                    results = self._find_for_method(method, target, _g_method_hub, method_cache, api_only=False)
                    methods_result['[' + class_key + ' ' + method.method_name + ']'] = results
                    if class_key not in method_cache:
                        method_cache[class_key] = {}
                    method_cache[class_key][method.method_name] = results
        return methods_result


def convert_inner_type(obj):
    if type(obj) == str:
        return obj
    elif type(obj) == int or type(obj) == float:
        return obj
    elif type(obj) == dict:
        converted_obj = {}
        for key in obj:
            converted_key = convert_inner_type(key)
            converted_value = convert_inner_type(obj[key])
            converted_obj[converted_key] = converted_value
        return converted_obj
    elif type(obj) == list:
        converted_obj = []
        for item in obj:
            converted_obj.append(convert_inner_type(item))
        return converted_obj
    elif type(obj) == tuple:
        converted_obj = []
        for item in obj:
            converted_obj.append(convert_inner_type(item))
        return converted_obj
    elif type(obj) == set:
        converted_obj = []
        for item in obj:
            converted_obj.append(convert_inner_type(item))
        return converted_obj
    else:
        return str(obj)
