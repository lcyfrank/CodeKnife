class MethodStorage:

    _method_instructions = []

    @classmethod
    def insert_instructions(cls, instructions):
        cls._method_instructions.append(instructions)

    @classmethod
    def get_instructions(cls, class_name, method_name):
        for _method_insn in cls._method_instructions:
            if (_method_insn.class_name == class_name and
                    _method_insn.method_name == method_name):
                return _method_insn
        return None

    @classmethod
    def list_all(cls):
        for _method_insn in cls._method_instructions:
            print(_method_insn.class_name + ": " + _method_insn.method_name)


class MethodBasicBlockStorage:

    _method_basic_block_instructions = []

    @classmethod
    def insert_instructions(cls, instruction):
        cls._method_basic_block_instructions.append(instruction)

    @classmethod
    def get_instructions(cls, identify):
        for _basic_block in cls._method_basic_block_instructions:
            if _basic_block.identify == identify:
                return _basic_block
        return None


class MethodBasicBlockInstructions:

    def __init__(self, identify):
        self.identify = identify
        self.instructions = []

        self.jump_to_block = None  # identify
        self.jump_condition = True

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
        self.entry_block = None
        self.all_blocks = {}  # <identity: block>

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
        self.instruction = instruction
        self.goto_insns = None
        self.block_data = None

    def goto(self, class_name, method_name):
        self.goto_insns = (class_name, method_name)

    def block_callback(self, block_data):
        self.block_data = block_data
