from models.inner_instruction import *
from models.cfg import *

def generate_cfg_block(block, info_provider, class_name, method_name, recursive=False):

    cfg_blocks = []
    cfg_block = None

    wait_for_follow = []

    for i in range((len(block.instructions))):
        instruction = block.instructions[i]
        if cfg_block is None:
            cfg_block = CFGBlock(hex(instruction.address))
            if len(wait_for_follow) > 0:
                for fol_block in wait_for_follow:
                    fol_block.goto_block(cfg_block.name)
                wait_for_follow = []

        if instruction.goto_insns:  # 如果有调用函数
            basic_info, imp_name = instruction.goto_insns
            if basic_info == '$Function':  # function
                if filter_oc_function(imp_name):
                    continue
                if recursive and basic_info != class_name and imp_name != method_name:  # 如果需要更进一步解析（防止递归）
                    recursive_function = info_provider(basic_info, imp_name)
                    if recursive_function is not None:
                        recursive_cfg = generate_cfg(recursive_function, info_provider, True)
                        # cfg_block.add_node(recursive_cfg)
                        cfg_block.goto_block(recursive_cfg.entry.name)  # 该块进入调用的函数
                        cfg_blocks.append(cfg_block)

                        for rec_block in recursive_cfg.all_blocks:  # 将深入的函数的块都加到当前 CFG 中
                            cfg_blocks.append(rec_block)
                            if rec_block.out:
                                rec_block.out = False  # 对于当前函数来说，这个块不是出口块
                                wait_for_follow.append(rec_block)

                        cfg_block = None
                        # cfg_block.add_node(recursive_cfg)
                        # cfg_blocks.append(cfg_block)
                        continue
                cfg_node = CFGNode(CFGNodeTypeFunction)
                cfg_node.function_name = imp_name
            else:
                if recursive and basic_info != class_name and imp_name != method_name:
                    # print('find recursive method')
                    # print(basic_info, imp_name)
                    recursive_method = info_provider(basic_info, imp_name)
                    if recursive_method is not None:
                        # print('find it')
                        recursive_cfg = generate_cfg(recursive_method, info_provider, True)
                        cfg_block.goto_block(recursive_cfg.entry.name)
                        cfg_blocks.append(cfg_block)

                        for rec_block in recursive_cfg.all_blocks:
                            cfg_blocks.append(rec_block)
                            if rec_block.out:
                                rec_block.out = False
                                wait_for_follow.append(rec_block)

                        cfg_block = None
                        continue
                cfg_node = CFGNode(CFGNodeTypeMethod)
                cfg_node.class_name = basic_info
                cfg_node.method_name = imp_name
            cfg_block.add_node(cfg_node)

    if cfg_block is not None:
        cfg_blocks.append(cfg_block)

    return cfg_blocks


def generate_cfg(method, info_provider, recursive=False):
    # print('Current generate CFG of method: %s in class: %s' % (method.method_name, method.class_name))

    wait_blocks_queue = []

    cfg_name = method.class_name + ': ' + method.method_name
    cfg = CFG(cfg_name)

    wait_blocks_queue.append(method.entry_block)

    while len(wait_blocks_queue) > 0:
        block = wait_blocks_queue[0]
        wait_blocks_queue = wait_blocks_queue[1:]

        cfg_blocks = generate_cfg_block(block, info_provider, method.class_name,
                                       method.method_name, recursive)
        if block.is_return:
            cfg_blocks[-1].out = True

        for cfg_block in cfg_blocks:
            cfg.add_block(cfg_block)

        if cfg.entry is None:
            cfg.entry = cfg_blocks[0]

        if not block.is_return:  # 含有 ret 的基本块应该肯定不会有 followed 的块
            if block.jump_to_block is not None and block.jump_to_block in method.all_blocks:
                cfg_blocks[-1].goto_block(block.jump_to_block)
                if cfg.get_block(block.jump_to_block) is None:
                    wait_blocks_queue.append(method.all_blocks[block.jump_to_block])

            if block.jump_condition and block.next_block is not None:
                cfg_blocks[-1].goto_block(block.next_block)
                if cfg.get_block(block.next_block) is None:
                    wait_blocks_queue.append(method.all_blocks[block.next_block])
    return cfg

    # for i in range(len(method.instructions)):
    #     instruction = method.instructions[i]
    #     if instruction.goto_insns:
    #         basic_info, imp_name = instruction.goto_insns
    #         if basic_info == '$Function':  # function
    #             if filter_oc_function(imp_name):
    #                 continue
    #             if recursive:
    #                 recursive_function = info_provider(basic_info, imp_name)
    #                 if recursive_function is not None:
    #                     recursive_cfg = generate_cfg(recursive_function, info_provider, True)
    #                     for recursive_cfg_node in recursive_cfg.nodes:
    #                         cfg.add_node(recursive_cfg_node)
    #                     continue
    #             cfg_node = CFGNode(CFGNodeTypeFunction)
    #             cfg_node.function_name = imp_name
    #         else:  # method
    #             if recursive:
    #                 recursive_method = info_provider(basic_info, imp_name)
    #                 if recursive_method is not None:
    #                     recursive_cfg = generate_cfg(recursive_method, info_provider, True)
    #                     for recursive_cfg_node in recursive_cfg.nodes:
    #                         cfg.add_node(recursive_cfg_node)
    #                     continue
    #             cfg_node = CFGNode(CFGNodeTypeMethod)
    #             cfg_node.class_name = basic_info
    #             cfg_node.method_name = imp_name
    #         cfg.add_node(cfg_node)
    # return cfg


def filter_oc_function(function):
    if function.startswith('_objc_'):
        return True
    return False