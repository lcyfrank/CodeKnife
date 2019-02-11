from models.inner_instruction import *
from models.cfg import *


def generate_cfg(method, info_provider, recursive=False):
    print('Current generate CFG of method: %s in class: %s' % (method.method_name, method.class_name))

    cfg_name = method.class_name + ': ' + method.method_name
    cfg = CFG(cfg_name)
    for i in range(len(method.instructions)):
        instruction = method.instructions[i]
        if instruction.goto_insns:
            basic_info, imp_name = instruction.goto_insns
            if basic_info == '$Function':  # function
                if filter_oc_function(imp_name):
                    continue
                if recursive:
                    recursive_function = info_provider(basic_info, imp_name)
                    if recursive_function is not None:
                        recursive_cfg = generate_cfg(recursive_function, info_provider, True)
                        for recursive_cfg_node in recursive_cfg.nodes:
                            cfg.add_node(recursive_cfg_node)
                        continue
                cfg_node = CFGNode(CFGNodeTypeFunction)
                cfg_node.function_name = imp_name
            else:  # method
                if recursive:
                    recursive_method = info_provider(basic_info, imp_name)
                    if recursive_method is not None:
                        recursive_cfg = generate_cfg(recursive_method, info_provider, True)
                        for recursive_cfg_node in recursive_cfg.nodes:
                            cfg.add_node(recursive_cfg_node)
                        continue
                cfg_node = CFGNode(CFGNodeTypeMethod)
                cfg_node.class_name = basic_info
                cfg_node.method_name = imp_name
            cfg.add_node(cfg_node)
    return cfg


def filter_oc_function(function):
    if function.startswith('_objc_'):
        return True
    return False
