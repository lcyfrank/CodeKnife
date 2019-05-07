MethodDataFlowTypeParameters = 0  # 从参数转过来的
MethodDataFlowTypeInstruction = 1  # 从指令返回值转过来的


class MethodDataFlow:

    def __init__(self, type, source):
        self.type = type
        self.source = source
        self.flow_to = []  # 数据流传向

    def flow(self, instruction, position):  # 流向的指令，position 是指参数的位置，调用者为 0
        self.flow_to.append((instruction, position))

    def describe(self):
        if self.type == MethodDataFlowTypeParameters:
            for to_item, position in self.flow_to:
                if type(to_item) == str:  # str type
                    if to_item == 'Out':  # Out
                        to_str = to_item
                        print('\t%s -> %s' % (self.source, to_str))
                else:
                    cls, mtd = to_item.goto_insns
                    to_str = '<' + hex(to_item.address) + '>' + ' ' + cls + ': ' + mtd + '(' + str(position) + ')'
                    print('\t%s -> %s' % (self.source, to_str))
        else:
            cls, mtd = self.source.goto_insns
            from_str = '<' + hex(self.source.address) + '>' + ' ' + cls + ': ' + mtd
            for to_item, position in self.flow_to:
                if type(to_item) == str:  # str type
                    if to_item == 'Out':  # Out
                        to_str = to_item
                        print('\t%s -> %s' % (from_str, to_str))
                else:
                    cls, mtd = to_item.goto_insns
                    to_str = '<' + hex(to_item.address) + '>' + ' ' + cls + ': ' + mtd + '(' + str(position) + ')'
                    print('\t%s -> %s' % (from_str, to_str))


class MethodBasicBlockInstructions:

    def __init__(self, identify):
        self.identify = identify
        self.instructions = []

        self.jump_to_block = None  # identify
        self.jump_condition = None  # 跳转条件，字符串

        self.is_return = False
        self.next_block = None  # identify

    def insert_instruction(self, instruction):
        self.instructions.append(instruction)

    def describe(self):
        for index in range(len(self.instructions)):
            ins = self.instructions[index]
            ins_str = ins.instruction
            if ins.goto_insns:
                class_name, method_name = ins.goto_insns
                ins_str += (" (" + class_name + ": " + method_name + ")")
            if index == len(self.instructions) - 1 and self.jump_to_block is not None:
                print(ins_str + " {Jump to ==> %s}" % self.jump_to_block)
            else:
                print(ins_str)


class MethodInstructions:

    def __init__(self, class_name, method_name):
        self.class_name = class_name
        self.method_name = method_name
        self.return_type = []  # 存储当前方法的返回值，list 类型是因为可能会出现不同的执行路径产生不同的返回值
        self.entry_block = None
        self.all_blocks = {}  # <identity: block>  这个 Block 也不是 OC 的 Block
        self.data_flows: {str: MethodDataFlow} = {}  # MethodDataFlow

    def describe(self):
        print("<%s: %s>" % (self.class_name, self.method_name))
        current_block = self.entry_block
        while current_block:
            current_block.describe()
            if current_block.next_block is not None:
                current_block = self.all_blocks[current_block.next_block]
            else:
                break

    def add_data_flow_from_parameter(self, parameter, destination, position):
        if parameter not in self.data_flows:
            data_flow = MethodDataFlow(MethodDataFlowTypeParameters, parameter)
            self.data_flows[parameter] = data_flow
        data_flow: MethodDataFlow = self.data_flows[parameter]
        data_flow.flow(destination, position)

    def add_data_flow_from_instruction(self, instruction, destination, position):
        if instruction not in self.data_flows:
            data_flow = MethodDataFlow(MethodDataFlowTypeInstruction, instruction)
            self.data_flows[instruction] = data_flow
        data_flow: MethodDataFlow = self.data_flows[instruction]
        data_flow.flow(destination, position)

    def add_data_flow_from_parameter_to_out(self, parameter):
        if parameter not in self.data_flows:
            data_flow = MethodDataFlow(MethodDataFlowTypeParameters, parameter)
            self.data_flows[parameter] = data_flow
        data_flow: MethodDataFlow = self.data_flows[parameter]
        data_flow.flow('Out', 0)

    def add_data_flow_from_instruction_to_out(self, instruction):
        if instruction not in self.data_flows:
            data_flow = MethodDataFlow(MethodDataFlowTypeInstruction, instruction)
            self.data_flows[instruction] = data_flow
        data_flow: MethodDataFlow = self.data_flows[instruction]
        data_flow.flow('Out', 0)

class Instruction:

    def __init__(self, instruction: str):
        self.address = 0
        self.instruction = instruction
        self.goto_insns: tuple = None  # tuple
        self.block_data = []  # 这个 Block 代表 OC 的 Block

    def goto(self, class_name, method_name):
        self.goto_insns = (class_name, method_name)

    def block_callback(self, block_name):
        self.block_data.append(('$Block', block_name))
