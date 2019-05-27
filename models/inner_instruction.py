MethodDataFlowTypeParameters = 0  # 从参数转过来的
MethodDataFlowTypeInstruction = 1  # 从指令返回值转过来的


class MethodDataFlow:

    def __init__(self, _type=0, source=None, mdf_dict=None):
        if mdf_dict is None:
            self.type = _type
            self.source = source
            self.flow_to = []  # 数据流传向
        else:
            self.type = mdf_dict['type']
            if self.type == MethodDataFlowTypeParameters:
                self.source = mdf_dict['source']
            else:
                self.source = Instruction(ins_dict=mdf_dict['source'])
            self.flow_to = []
            flow_to_list = mdf_dict['flow_to']
            for to_item, position in flow_to_list:
                if type(to_item) == dict:
                    self.flow_to.append((Instruction(ins_dict=to_item), position))
                else:
                    self.flow_to.append((to_item, position))

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

    def convert_to_dict(self):
        mdf_dict = {
            'type': self.type
        }
        if self.type == MethodDataFlowTypeParameters:
            mdf_dict['source'] = self.source
        else:
            mdf_dict['source'] = self.source.convert_to_dict()

        flow_to_list = []
        for to_item, position in self.flow_to:
            if type(to_item) == str:
                flow_to_list.append((to_item, position))
            else:
                flow_to_list.append((to_item.convert_to_dict(), position))
        mdf_dict['flow_to'] = flow_to_list
        return mdf_dict


class MethodBasicBlockInstructions:

    def __init__(self, identify=None, mbbi_dict=None):
        if mbbi_dict is None:
            self.identify = identify
            self.instructions = []

            self.jump_to_block = None  # identify
            self.jump_condition = None  # 跳转条件，字符串

            self.is_return = False
            self.next_block = None  # identify
        else:
            self.identify = mbbi_dict['identify']
            self.jump_to_block = mbbi_dict['jump_to_block']
            self.jump_condition = mbbi_dict['jump_condition']
            self.is_return = mbbi_dict['is_return']
            self.next_block = mbbi_dict['next_block']
            self.instructions = []
            for instruction_dict in mbbi_dict['instructions']:
                self.instructions.append(Instruction(ins_dict=instruction_dict))

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

    def convert_to_dict(self):
        mbbi_dict = {'identify': self.identify, 'jump_to_block': self.jump_to_block,
                     'jump_condition': self.jump_condition, 'is_return': self.is_return,
                     'next_block': self.next_block, 'instructions': []}
        for instruction in self.instructions:
            mbbi_dict['instructions'].append(instruction.convert_to_dict())

        return mbbi_dict


class MethodInstructions:

    def __init__(self, class_name=None, method_name=None, mi_dict=None):
        if mi_dict is None:
            self.class_name = class_name
            self.method_name = method_name
            self.return_type = []  # 存储当前方法的返回值，list 类型是因为可能会出现不同的执行路径产生不同的返回值
            self.entry_block = None
            self.all_blocks = {}  # <identity: block>  这个 Block 也不是 OC 的 Block
            self.data_flows: {str: MethodDataFlow} = {}  # MethodDataFlow
        else:
            self.class_name = mi_dict['class_name']
            self.method_name = mi_dict['method_name']
            self.return_type = mi_dict['return_type']
            self.entry_block = MethodBasicBlockInstructions(mbbi_dict=mi_dict['entry_block'])
            self.all_blocks = {}
            for identity in mi_dict['all_blocks']:
                self.all_blocks[identity] = MethodBasicBlockInstructions(mbbi_dict=mi_dict['all_blocks'][identity])
            self.data_flows = {}
            data_flows_dict = eval(mi_dict['data_flows'])
            for data_flow_key in data_flows_dict:
                if data_flow_key.startswith('Parameter'):
                    self.data_flows[data_flow_key] = MethodDataFlow(mdf_dict=data_flows_dict[data_flow_key])
                else:
                    self.data_flows[data_flow_key] = MethodDataFlow(mdf_dict=data_flows_dict[data_flow_key])

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
            self.data_flows[hex(instruction.address)] = data_flow
        data_flow: MethodDataFlow = self.data_flows[hex(instruction.address)]
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
            self.data_flows[hex(instruction.address)] = data_flow
        data_flow: MethodDataFlow = self.data_flows[hex(instruction.address)]
        data_flow.flow('Out', 0)

    def convert_to_dict(self):
        mi_dict = {
            'class_name': self.class_name,
            'method_name': self.method_name,
            'return_type': self.return_type,
            'entry_block': self.entry_block.convert_to_dict(),
            'all_blocks': {},
            'data_flows': None
        }
        for identify in self.all_blocks:
            mi_dict['all_blocks'][identify] = self.all_blocks[identify].convert_to_dict()

        data_flows = {}
        for data_flow_key in self.data_flows:
            if type(data_flow_key) == str:
                data_flows[data_flow_key] = self.data_flows[data_flow_key].convert_to_dict()
            else:
                data_flows[str(data_flow_key.convert_to_dict())] = self.data_flows[data_flow_key].convert_to_dict()
        mi_dict['data_flows'] = str(data_flows)
        return mi_dict


class Instruction:

    def __init__(self, instruction: str=None, ins_dict=None):
        if ins_dict is None:
            self.address = 0
            self.instruction = instruction
            self.goto_insns: tuple = None  # tuple
            self.block_data = []  # 这个 Block 代表 OC 的 Block
        else:
            self.address = ins_dict['address']
            instruction = ins_dict['instruction']
            self.instruction = instruction.replace('\\t', '\t')
            if len(ins_dict['goto_insns']) > 0:
                goto_insns = ins_dict['goto_insns'].split(' ')
                _class = goto_insns[0]
                method = goto_insns[1]
                self.goto_insns = (_class, method)
            else:
                self.goto_insns = None

            block_datas = []
            for block_name in ins_dict['block_data']:
                block_datas.append(('$Block', block_name))
            self.block_data = block_datas

    def goto(self, class_name, method_name):
        self.goto_insns = (class_name, method_name)

    def block_callback(self, block_name):
        self.block_data.append(('$Block', block_name))

    def convert_to_dict(self):
        if self.goto_insns is not None:
            _class, method = self.goto_insns
            goto_insns_str = _class + ' ' + method
        else:
            goto_insns_str = ''

        block_datas = []
        for _, block_name in self.block_data:
            block_datas.append(block_name)

        instruction = self.instruction.replace('\t', '\\t')
        ins_dict = {'address': self.address, 'instruction': instruction,
                    'goto_insns': goto_insns_str, 'block_data': block_datas}
        return ins_dict


class CSInstruction:

    def __init__(self, csi_dict=None):
        if csi_dict is None:
            self.address = 0
            self.id = 0
            self.operands = []
            self.mnemonic = None
            self.bytes = None
            self.op_str = None
            self.comment = None
        else:
            self.address = csi_dict['address']
            self.id = csi_dict['id']
            self.mnemonic = csi_dict['mnemonic']
            self.bytes = bytes.fromhex(csi_dict['bytes'])
            self.op_str = csi_dict['op_str']
            self.comment = csi_dict['comment']
            self.operands = []
            for operand_dict in csi_dict['operands']:
                self.operands.append(CSOperand(cso_dict=operand_dict))

    def convert_to_dict(self):
        csi_dict = {
            'address': self.address,
            'id': self.id,
            'operands': [],
            'mnemonic': self.mnemonic,
            'bytes': self.bytes.hex(),
            'op_str': self.op_str,
            'comment': self.comment
        }

        for operand in self.operands:
            csi_dict['operands'].append(operand.convert_to_dict())

        return csi_dict


class CSOperand:

    def __init__(self, cso_dict=None):
        if cso_dict is None:
            self.type = 0
            self.imm = 0
            self.reg = None  # eg. x1
            self.mem = None
        else:
            self.type = cso_dict['type']
            self.imm = cso_dict['imm']
            self.reg = cso_dict['reg']
            self.mem = CSMemory(cso_dict['mem'])

    def convert_to_dict(self):
        cso_dict = {
            'type': self.type,
            'imm': self.imm,
            'reg': self.reg,
            'mem': self.mem.convert_to_dict() if self.mem is not None else None
        }
        return cso_dict


class CSMemory:

    def __init__(self, csm_dict=None):
        if csm_dict is None:
            self.base = None  # eg. x1
            self.index = 0
            self.disp = 0
        else:
            self.base = csm_dict['base']
            self.index = csm_dict['index']
            self.disp = csm_dict['disp']

    def convert_to_dict(self):
        return self.__dict__.copy()
