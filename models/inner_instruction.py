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


class MethodInstructions:

    def __init__(self, class_name, method_name):
        self.class_name = class_name
        self.method_name = method_name
        self.instructions = []

    def insert_instruction(self, instruction):
        self.instructions.append(instruction)

    def describe(self):
        for ins in self.instructions:
            ins_str = ins.instruction
            if ins.goto_insns:
                class_name, method_name = ins.goto_insns
                ins_str += (" (" + class_name + ": " + method_name + ")")
            print(ins_str)


class Instruction:

    def __init__(self, instruction):
        self.instruction = instruction
        self.goto_insns = None

    def goto(self, class_name, method_name):
        self.goto_insns = (class_name, method_name)
