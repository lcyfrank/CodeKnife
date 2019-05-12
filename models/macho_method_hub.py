from models.inner_instruction import MethodInstructions


class MachoMethodHub:

    def __init__(self):
        self.cs_insns = {}  # Capstone 解析出来的指令集
        self.method_insns = {}  # 指令模拟执行之后解析出来的指令集  {class_name: [method_insns]}

    def insert_cs_insn(self, cs_insn):  # list [CSInstruction]
        self.cs_insns[hex(cs_insn[0].address)] = cs_insn

    def insert_method_insn(self, method_insn):
        print(method_insn)
        if method_insn.class_name not in self.method_insns:
            self.method_insns[method_insn.class_name] = []
        self.method_insns[method_insn.class_name].append(method_insn)

    def get_cs_insn(self, addr):
        if addr in self.cs_insns:
            return self.cs_insns[addr]
        return None

    def get_method_insn(self, class_name, method_name):
        if class_name in self.method_insns:
            for method in self.method_insns[class_name]:
                if method.method_name == method_name:
                    return method
        return None

    def list_all_methods(self):
        for cls in self.method_insns:
            for m in self.method_insns[cls]:
                print(cls + ' ' + m.method_name)

    def convert_to_dict(self):
        mmh_dict = {}
        cs_insns_dict = {}
        for key in self.cs_insns:
            instruction_list = []
            for insn in self.cs_insns[key]:
                instruction_list.append(insn.convert_to_dict())
            cs_insns_dict[key] = instruction_list
        mmh_dict['cs_insns'] = cs_insns_dict

        method_insns_dict = {}
        for class_name in self.method_insns:
            method_insns_dict[class_name] = []
            class_methods = self.method_insns[class_name]
            for method_insn in class_methods:
                method_insns_dict[class_name].append(method_insn.convert_to_dict())
        mmh_dict['method_insns'] = method_insns_dict

        return mmh_dict
