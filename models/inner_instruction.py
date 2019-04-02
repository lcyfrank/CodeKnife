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

    def describe(self):
        print("<%s: %s>" % (self.class_name, self.method_name))
        current_block = self.entry_block
        while current_block:
            current_block.describe()
            if current_block.next_block is not None:
                current_block = self.all_blocks[current_block.next_block]
            else:
                break


class Instruction:

    def __init__(self, instruction):
        self.address = 0
        self.instruction = instruction
        self.goto_insns = None
        self.block_data = []  # 这个 Block 代表 OC 的 Block

    def goto(self, class_name, method_name):
        self.goto_insns = (class_name, method_name)

    def block_callback(self, block_name):
        self.block_data.append(('$Block', block_name))
