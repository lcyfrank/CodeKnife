from queue import Queue
from models.inner_instruction import *

_g_result_list = []
_g_mach_info = None
_g_method_hub = None

_g_messages_queue: Queue = None

caller = None
callee = None
notification = None
data_flow = None


def execute_checker(checker_code: str, mach_info, method_hub, messages_queue=None):
    global _g_result_list
    global _g_mach_info
    global _g_method_hub

    global _g_messages_queue

    global caller
    global callee
    global notification
    global data_flow

    _g_result_list = []
    _g_mach_info = mach_info
    _g_method_hub = method_hub

    _g_messages_queue = messages_queue

    caller = CKCaller()
    callee = CKCallee()
    notification = CKNotification()
    data_flow = CKDataFlow()

    _g_messages_queue.put({'msg': 'begin', 'type': 1})

    try:
        code = compile(checker_code, '<string>', 'exec')
    except Exception as e:
        _g_messages_queue.put({'msg': str(e), 'type': -1})
        return
    try:
        exec(code)
    except Exception as e:
        _g_messages_queue.put({'msg': str(e), 'type': -1})

    _g_messages_queue.put({'msg': 'end', 'type': 1})


def ck_log(msg):
    global _g_messages_queue

    for msg_item in convert_inner_type(msg):
        _g_messages_queue.put({'msg': msg_item, 'type': 0})


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
                            result = self._find_for_method(called_method, target, method_hub, method_cache,
                                                           recursive_set.copy())
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
                            result = self._find_function_for_method(called_method, target, method_hub, method_cache,
                                                                    recursive_set.copy())
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
                            apis = self._find_for_method(called_method, target, method_hub, method_cache,
                                                         recursive_set.copy())
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


class CKNotification:

    def handler(self, notifications: list):
        global _g_mach_info

        mach_object = _g_mach_info.mach_objects[0]
        handlers = {}
        for noti in notifications:
            if noti == '*':
                for notification_name in mach_object.notification_handler:
                    handlers[notification_name] = []
                    for observer, selector in mach_object.notification_handler[notification_name]:
                        handlers[notification_name].append((observer, selector))
            else:
                handlers[noti] = []
                if noti in mach_object.notification_handler:
                    for observer, selector in mach_object.notification_handler[noti]:
                        handlers[noti].append((observer, selector))
        return handlers

    def poster(self, notifications: list):
        global _g_mach_info

        mach_object = _g_mach_info.mach_objects[0]
        posters = {}
        for noti in notifications:
            if noti == '*':
                for notification_name in mach_object.notification_poster:
                    posters[notification_name] = []
                    for observer, selector in mach_object.notification_poster[notification_name]:
                        posters[notification_name].append((observer, selector))
            else:
                posters[noti] = []
                if noti in mach_object.notification_poster:
                    for observer, selector in mach_object.notification_poster[noti]:
                        posters[noti].append((observer, selector))
        return posters


class CKDataFlow:

    def flow_from(self, methods: dict, source_from: list):
        global _g_method_hub
        data_flows = {}
        for class_name in methods:
            class_methods = methods[class_name]
            for method_name in class_methods:
                method_insn = _g_method_hub.get_method_insn(class_name, method_name)
                if method_insn is not None:
                    data_flow_key = '[' + class_name + ' ' + method_name + ']'
                    data_flows[data_flow_key] = {}
                    for source_class, source_method in source_from:
                        if len(source_class) == 0:
                            if source_method in method_insn.data_flows:
                                data_flows[data_flow_key][source_method] = []
                                data_flow = method_insn.data_flows[source_method]
                                for flow_to, position in data_flow.flow_to:
                                    if type(flow_to) == str:
                                        data_flows[data_flow_key][source_method].append(
                                            flow_to + ' (' + str(position) + ')')
                                    else:
                                        flow_to_class, flow_to_method = flow_to.goto_insns
                                        flow_to_str = '[' + flow_to_class + ' ' + flow_to_method + ']'
                                        data_flows[data_flow_key][source_method].append(
                                            flow_to_str + '(' + str(position) + ')')
                        else:
                            for df_key in method_insn.data_flows:
                                data_flow = method_insn.data_flows[df_key]
                                if data_flow.type == MethodDataFlowTypeParameters:
                                    continue
                                check_class, check_method = data_flow.source.goto_insns
                                class_matched = source_class == '*' or check_class == source_class
                                method_matched = source_method == '*' or source_method == check_method
                                if not class_matched or not method_matched:
                                    continue
                                source_key = '[' + check_class + ' ' + check_method + ']'
                                data_flows[data_flow_key][source_key] = []
                                for flow_to, position in data_flow.flow_to:
                                    if type(flow_to) == str:
                                        data_flows[data_flow_key][source_key].append(
                                            flow_to + ' (' + str(position) + ')')
                                    else:
                                        flow_to_class, flow_to_method = flow_to.goto_insns
                                        flow_to_str = '[' + flow_to_class + ' ' + flow_to_method + ']'
                                        data_flows[data_flow_key][source_key].append(
                                            flow_to_str + '(' + str(position) + ')')
        return data_flows


def convert_inner_type(obj, prefix=''):
    if type(obj) == str:
        return [prefix + obj]
    elif type(obj) == int or type(obj) == float:
        return [prefix + str(obj)]
    elif type(obj) == dict:
        converted_obj = [prefix + '{']
        for key in obj:
            converted_key = convert_inner_type(key, prefix=prefix + '&nbsp;&nbsp;')
            converted_key[-1] = converted_key[-1] + ': '
            converted_obj += converted_key
            converted_value = convert_inner_type(obj[key], prefix=prefix + '&nbsp;&nbsp;&nbsp;&nbsp;')
            converted_value[-1] = converted_value[-1] + ','
            converted_obj += converted_value
        converted_obj += [prefix + '}']
        return converted_obj
    elif type(obj) == list:
        converted_obj = [prefix + '[']
        for item in obj:
            converted_items = convert_inner_type(item, prefix=prefix + '&nbsp;&nbsp;')
            if len(converted_items) > 0:
                converted_items[-1] = converted_items[-1] + ','
            converted_obj += converted_items
        converted_obj += [prefix + ']']
        return converted_obj
    elif type(obj) == tuple:
        converted_obj = [prefix + '(']
        for item in obj:
            converted_items = convert_inner_type(item, prefix=prefix + '&nbsp;&nbsp;')
            if len(converted_items) > 0:
                converted_items[-1] = converted_items[-1] + ','
            converted_obj += converted_items
        converted_obj += [prefix + ')']
        return converted_obj
    elif type(obj) == set:
        converted_obj = [prefix + '{']
        for item in obj:
            converted_items = convert_inner_type(item, prefix=prefix + '&nbsp;&nbsp;')
            if len(converted_items) > 0:
                converted_items[-1] = converted_items[-1] + ','
            converted_obj += converted_items
        converted_obj += [prefix + '}']
        return converted_obj
    else:
        return [prefix + str(obj)]
