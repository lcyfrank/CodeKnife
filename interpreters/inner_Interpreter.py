import ctypes
from capstone import *
from capstone.arm64 import *

SELF_POINTER = -0x1000000
CURRENT_SELECTOR = -0x2000000


class ExecuteContext:

    def __init__(self):
        self.variable_count = 0

        self.data_flow = {}  # var_name: [(from, to)]
        self.variable_from = {}  # var_name: from

        self.register_variable = {}  # register_name: var_name
        self.memory_variable = {}  # memory: var_name

    def add_variable(self, reg_name):
        variable_name = 'var_' + str(self.variable_count)
        self.variable_count += 1
        self.register_variable[reg_name] = variable_name

    def add_memory_variable(self, memory):
        variable_name = 'var_' + str(self.variable_count)
        self.variable_count += 1
        self.memory_variable[memory] = variable_name

    def mov_regs(self, src_reg, dst_reg):
        if src_reg in self.register_variable:
            self.register_variable[dst_reg] = self.register_variable[src_reg]
        else:
            if dst_reg in self.register_variable:
                del self.register_variable[dst_reg]

    def ldr_memory(self, src_memory, dst_reg):
        if src_memory in self.memory_variable:
            self.register_variable[dst_reg] = self.memory_variable[src_memory]
        else:
            if dst_reg in self.register_variable:
                del self.register_variable[dst_reg]

    def str_memory(self, src_reg, dst_memory):
        if src_reg in self.register_variable:
            self.memory_variable[dst_memory] = self.register_variable[src_reg]
        else:
            if dst_memory in self.memory_variable:
                del self.memory_variable[dst_memory]

    def var_from(self, var_name, from_item):  # from_item may be str or Instruction
        var_index = int(var_name[4:])
        if var_index < self.variable_count:
            self.variable_from[var_name] = from_item

    def add_from_to(self, var_name, from_item, to_item, position):  # to_item is Instruction and position is parameter position
        if var_name not in self.data_flow:
            self.data_flow[var_name] = []
        self.data_flow[var_name].append((from_item, to_item, position))


class Register:

    def __init__(self, index):
        self.index = index
        self.low = ctypes.c_int32(0).value
        self.high = ctypes.c_int32(0).value
        # self.is_memory_content = False

    def clear(self):
        self.low = ctypes.c_int32(0).value
        self.high = ctypes.c_int32(0).value
        # self.is_memory_content = False

    @property
    def value(self):
        value = self.high << 32
        value += self.low
        return ctypes.c_int64(value).value

    @value.setter
    def value(self, value):
        self.high = value >> 32
        self.low = value & 0xffffffff


class FloatRegister:

    def __init__(self, index):
        self.index = index
        self.value = 0

    def clear(self):
        self.value = 0


    # @property
    # def is_memory_content(self):
    #     return False

    # @is_memory_content.setter
    # def is_memory_content(self, value):
    #     pass
InterpreterArch64 = 0
InterpreterArch32 = 1


class Interpreter:

    def __init__(self, context=None, memory_provider=None, store_notify=None, arch=InterpreterArch64, parameters=[]):
        self.saved_state = {}

        self.gen_regs = [Register(i) for i in range(31)]
        self.float_regs = [FloatRegister(i) for i in range(32)]

        self.context: ExecuteContext = context

        self.wzr = Register(-1)
        self.xzr = Register(-1)
        self.wsp = Register(-1)
        self.sp = Register(-1)
        self.pc = Register(-1)

        self.condition_flag = 0

        self.memory = {}

        self.tracking = {}  # 记录寄存器和内存值的轨迹

        self.memory_provider = memory_provider
        self.store_notify = store_notify

        # 处理参数
        register_argument_count = 4 if arch == InterpreterArch32 else 8
        if len(parameters) <= register_argument_count:
            int_count = 0
            float_count = 0
            for i in range(len(parameters)):
                # (type, length, value)
                argument_type, length, value = parameters[i]
                if argument_type == 'int':
                    self.gen_regs[int_count].value = value
                    self.context.add_variable('gen_' + str(int_count))
                    self.context.var_from('var_' + str(self.context.variable_count - 1), 'Parameter_' + str(i))
                    int_count += 1
                else:
                    self.float_regs[float_count].value = value
                    self.context.add_variable('float_' + str(float_count))
                    self.context.var_from('var_' + str(self.context.variable_count - 1), 'Parameter_' + str(i))
                    float_count += 1
        else:
            int_count = 0
            float_count = 0
            for i in range(register_argument_count):
                argument_type, length, value = parameters[i]
                if argument_type == 'int':
                    self.gen_regs[int_count].value = value
                    self.context.add_variable('gen_' + str(int_count))
                    self.context.var_from('var_' + str(self.context.variable_count - 1), 'Parameter_' + str(i))
                    int_count += 1
                else:
                    self.float_regs[float_count].value = value
                    self.context.add_variable('float_' + str(float_count))
                    self.context.var_from('var_' + str(self.context.variable_count - 1), 'Parameter_' + str(i))
                    float_count += 1
            # 超过 4/8 个参数存到栈里
            # 先不对齐了
            for i in range(register_argument_count, len(parameters)):
                argument_type, length, value = parameters[i]
                if argument_type == 'int':
                    self.memory[hex(self.sp.value)] = value
                    self.context.add_memory_variable(hex(self.sp.value))
                    self.context.var_from('var_' + str(self.context.variable_count - 1), 'Parameter_' + str(i))
                    self.sp.value = (self.sp.value - length)
                else:
                    self.float_regs[float_count].value = value
                    self.context.add_variable('float_' + str(float_count))
                    self.context.var_from('var_' + str(self.context.variable_count - 1), 'Parameter_' + str(i))

    def save_state(self, key):

        memory_state = {}
        for m_key in self.memory:
            memory_state[m_key] = self.memory[m_key]

        gen_regs_state = []
        for reg in self.gen_regs:
            gen_regs_state.append(reg.value)

        float_regs_state = []
        for reg in self.float_regs:
            float_regs_state.append(reg.value)

        state = {
            'memory': memory_state,
            'wzr': self.wzr.value,
            'xzr': self.xzr.value,
            'wsp': self.wsp.value,
            'sp': self.sp.value,
            'pc': self.pc.value,
            'gen_regs': gen_regs_state,
            'float_regs': float_regs_state,
            'condition_flag': self.condition_flag,
            'context': self.context.register_variable.copy(),
            'memory_context': self.context.memory_variable.copy()
        }
        self.saved_state[key] = state

    def restore_state(self, key):
        if key in self.saved_state:
            state = self.saved_state[key]
            self.memory = {}
            for m_key in state['memory']:
                self.memory[m_key] = state['memory'][m_key]
            self.wzr.value = state['wzr']
            self.xzr.value = state['xzr']
            self.wsp.value = state['wsp']
            self.sp.value = state['sp']
            self.pc.value = state['pc']

            for reg in self.gen_regs:
                index = self.gen_regs.index(reg)
                reg.value = state['gen_regs'][index]

            for reg in self.float_regs:
                index = self.float_regs.index(reg)
                reg.value = state['float_regs'][index]
            self.condition_flag = state['condition_flag']
            self.context.register_variable = state['context'].copy()
            self.context.memory_variable = state['memory_context'].copy()
        else:
            print('Do not contain state of key:', key)

    def modify_regs(self, reg, value):
        if not type(value) == int:
            return False
        if reg.isdigit():
            reg_index = int(reg)
            self.gen_regs[reg_index].value = value
            # 修改了寄存器的值之后，同时要把对应的变量给删掉
            if 'gen_' + reg in self.context.register_variable:
                # if self.context.register_variable['gen_' + reg] in self.context.variable_from:
                #     del self.context.variable_from[self.context.register_variable['gen_' + reg]]
                del self.context.register_variable['gen_' + reg]


    def modify_memory(self, address, value):
        self.memory[hex(address)] = value

    def current_state(self):
        for i in range(len(self.gen_regs)):
            reg = self.gen_regs[i]
            print("x%d: %s" % (i, hex(reg.value)))
        print("wzr: %s" % hex(self.wzr.value))
        print("xzr: %s" % hex(self.xzr.value))
        print("wsp: %s" % hex(self.wsp.value))
        print("sp: %s" % hex(self.sp.value))
        print("pc: %s" % hex(self.pc.value))
        print(self.memory)

    def clear_regs(self):
        for reg in self.gen_regs:
            reg.clear()
        self.wzr.clear()
        self.xzr.clear()
        self.wsp.clear()
        self.sp.clear()
        self.pc.clear()
        # self.memory = {hex(0-0x30):SUPER_POINTER}

    def interpret_code(self, codes, begin=0, end=-1):
        i = begin
        if end == -1:
            end = len(codes)
        while i < end:
            insn = codes[i]
            if (insn.id == ARM64_INS_SUB or
                    insn.id == ARM64_INS_SBC):
                self.handle_sub(insn)
            elif (insn.id == ARM64_INS_ADD or
                  insn.id == ARM64_INS_ADC):
                self.handle_add(insn)
            elif (insn.id == ARM64_INS_STP or
                  insn.id == ARM64_INS_STR or
                  insn.id == ARM64_INS_STUR):
                self.handle_store_register(insn)
            elif (insn.id == ARM64_INS_ADRP or
                  insn.id == ARM64_INS_ADR):
                self.handle_adrp(insn)
            elif (insn.id == ARM64_INS_LDR or
                  insn.id == ARM64_INS_LDUR):
                self.handle_load_register(insn, length=8)
            elif (insn.id == ARM64_INS_LDRSW or
                  insn.id == ARM64_INS_LDURSW):
                self.handle_load_register(insn, length=4)
            elif (insn.id == ARM64_INS_LDRH or
                  insn.id == ARM64_INS_LDRSH or
                  insn.id == ARM64_INS_LDURH or
                  insn.id == ARM64_INS_LDURSH):
                self.handle_load_register(insn, length=2)
            elif (insn.id == ARM64_INS_LDRB or
                  insn.id == ARM64_INS_LDRSB or
                  insn.id == ARM64_INS_LDURB or
                  insn.id == ARM64_INS_LDURSB):
                self.handle_load_register(insn, length=1)
            elif (insn.id == ARM64_INS_LDP or
                  insn.id == ARM64_INS_LDPSW or
                  insn.id == ARM64_INS_LDNP):
                self.handle_load_pair(insn)
            elif (insn.id == ARM64_INS_MOV or
                  insn.id == ARM64_INS_MOVK or
                  insn.id == ARM64_INS_MOVN or
                  insn.id == ARM64_INS_MOVZ or
                  insn.id == ARM64_INS_FMOV or
                  insn.id == ARM64_INS_SMOV or
                  insn.id == ARM64_INS_UMOV):
                self.handle_move(insn)
            elif (insn.id == ARM64_INS_ORR or
                  insn.id == ARM64_INS_ORN):
                self.handle_orr(insn)
            elif insn.id == ARM64_INS_AND:
                self.handle_and(insn)
            elif (insn.id == ARM64_INS_CMP or
                  insn.id == ARM64_INS_CMN or
                  insn.id == ARM64_INS_TST):
                self.handle_cmp(insn)
            i += 1

    def get_register(self, name):
        if name == "sp":
            return self.sp
        if name == "wzr":
            return self.wzr
        if name == "xzr":
            return self.xzr
        if name == "wsp":
            return self.wsp
        if name == "pc":
            return self.pc
        if (name.startswith("x") or
            name.startswith("w")):
            reg_index = int(name[1:])
            return self.gen_regs[reg_index]
        if (name.startswith("v") or
            name.startswith("d") or
            name.startswith("q") or
            name.startswith("s") or
            name.startswith("h") or
            name.startswith("b")):
            reg_index = int(name[1:])
            return self.float_regs[reg_index]
        print(name)

    def handle_cmp(self, insn):
        tracking = []
        operand_1 = insn.operands[0]
        operand_2 = insn.operands[1]

        value_1 = 0
        value_2 = 0

        # 标志位
        z = 0
        c = 0
        v = 0
        n = 0

        if operand_1.type == ARM64_OP_IMM:
            value_1 = operand_1.imm
            tracking.append('#' + str(value_1))
        elif operand_1.type == ARM64_OP_REG:
            reg_name = insn.reg_name(operand_1.reg)
            register = self.get_register(reg_name)
            value_1 = register.value
            tracking.append(reg_name)

        if operand_2.type == ARM64_OP_IMM:
            value_2 = operand_2.imm
            tracking.append('#' + str(value_2))
        elif operand_2.type == ARM64_OP_REG:
            reg_name = insn.reg_name(operand_2.reg)
            register = self.get_register(reg_name)
            value_2 = register.value
            tracking.append(reg_name)

        if insn.id == ARM64_INS_CMP or insn.id == ARM64_INS_CMN:
            if insn.id == ARM64_INS_CMN:
                value_2 = -value_2

            if value_1 == value_2:
                z = 1
            else:
                z = 0

            if value_1 < value_2:
                n = 1
            else:
                n = 0

            un_value_1 = value_1 & 0xffffffffffffffff
            un_value_2 = value_2 & 0xffffffffffffffff
            if un_value_1 >= un_value_2:
                c = 1
            else:
                c = 0

            if value_1 + value_2 > 0xffffffffffffffff:
                v = 1
            else:
                v = 0

        elif insn.id == ARM64_INS_TST:
            result = value_1 & value_2
            if result == 0:
                z = 1
            else:
                z = 0

        # nvzc
        self.condition_flag = (n << 3 +
                               v << 2 +
                               c << 1 +
                               z)
        self.tracking['condition'] = tracking

    # 还没有处理 orr/and/add/sub 四个运算
    def handle_orr(self, insn):
        tracking = []
        result = 0
        for j in range(1, len(insn.operands)):
            operand = insn.operands[j]
            if operand.type == ARM64_OP_REG:
                reg_name = insn.reg_name(operand.reg)
                register = self.get_register(reg_name)
                result |= register.value
                tracking.append(reg_name)
            elif operand.type == ARM64_OP_IMM:
                result |= operand.imm
                tracking.append('#' + str(operand.imm))
        dest = insn.operands[0]
        if dest.type == ARM64_OP_REG:
            reg_name = insn.reg_name(dest.reg)
            self.tracking[reg_name] = tracking
            register = self.get_register(reg_name)
            register.value = result

    def handle_and(self, insn):
        tracking = []
        result = 0
        for j in range(1, len(insn.operands)):
            operand = insn.operands[j]
            if operand.type == ARM64_OP_REG:
                reg_name = insn.reg_name(operand.reg)
                register = self.get_register(reg_name)
                result &= register.value
                tracking.append(reg_name)
            elif operand.type == ARM64_OP_IMM:
                result &= operand.imm
                tracking.append('#' + str(operand.imm))
        dest = insn.operands[0]
        if dest.type == ARM64_OP_REG:
            reg_name = insn.reg_name(dest.reg)
            self.tracking[reg_name] = tracking
            register = self.get_register(reg_name)
            register.value = result

    def handle_move(self, insn):
        tracking = []
        dest_register_name = insn.reg_name(insn.operands[0].reg)
        dest_register = self.get_register(dest_register_name)
        source_value = 0
        source = insn.operands[1]
        if source.type == ARM64_OP_IMM:
            source_value = source.imm
            tracking.append('#' + str(source_value))
            # dest_register.is_memory_content = False
            dest_register.bias = 0
        elif source.type == ARM64_OP_REG:
            source_register = self.get_register(insn.reg_name(source.reg))
            source_value = source_register.value
            tracking.append(insn.reg_name(source.reg))

            if type(source_register) == Register:
                if source_register in self.gen_regs:
                    context_src_register = 'gen_' + str(self.gen_regs.index(source_register))
                else:
                    context_src_register = 'gen_' + insn.reg_name(source.reg)
            else:
                context_src_register = 'float_' + str(self.float_regs.index(source_register))
            if context_src_register in self.context.register_variable:
                context_dst_register = None
                if type(dest_register) == Register:
                    context_dst_register = 'gen_' + str(self.gen_regs.index(dest_register))
                else:
                    context_dst_register = 'float_' + str(self.float_regs.index(dest_register))
                self.context.mov_regs(context_src_register, context_dst_register)
        dest_register.value = source_value
        self.tracking[dest_register_name] = tracking

    def handle_load_register(self, insn, length=8):
        tracking = []
        memory_operand = insn.operands[-1].mem
        memory_reg_name = insn.reg_name(memory_operand.base)
        if memory_reg_name is None:  # 当内存就是立即数的时候
            memory_str = insn.op_str
            memory_str_index = memory_str.find('#') + 1
            memory_str = memory_str[memory_str_index:]
            memory = int(memory_str, 16)
        else:
            memory_reg = self.get_register(memory_reg_name)
            memory_disp = memory_operand.disp
            memory = memory_reg.value + memory_disp
        tracking.append('[' + str(memory) + ']')
        for j in range(0, len(insn.operands) - 1):
            operand = insn.operands[j]
            if operand.type == ARM64_OP_REG:
                reg_name = insn.reg_name(operand.reg)
                register = self.get_register(reg_name)

                if hex(memory + j * length) in self.memory:
                    memory_value = self.memory[hex(memory + j * length)]
                    wrap = 0xff
                    for i in range(1, length):
                        wrap = (wrap << 8) + 0xff
                    memory_value = memory_value & wrap
                    register.value = memory_value
                else:
                    if self.memory_provider != None:
                        memory_value = self.memory_provider(memory + j * length)
                    else:
                        memory_value = 0
                    wrap = 0xff
                    for i in range(1, length):
                        wrap = (wrap << 8) + 0xff
                    memory_value = memory_value & wrap
                    self.memory[hex(memory + j * length)] = memory_value
                    register.value = self.memory[hex(memory + j * length)]

                if type(register) == Register:
                    if register in self.gen_regs:
                        context_register = 'gen_' + str(self.gen_regs.index(register))
                    else:
                        context_register = 'gen_' + insn.reg_name(operand.reg)
                else:
                    context_register = 'float_' + str(self.float_regs.index(register))
                self.context.ldr_memory(hex(memory + j * length), context_register)
                self.tracking[reg_name] = tracking

    def handle_load_pair(self, insn):
        self.handle_load_register(insn)

    def handle_store_register(self, insn, length=8):
        memory_operand = insn.operands[-1].mem
        memory_reg_name = insn.reg_name(memory_operand.base)
        if memory_reg_name is None:
            memory_str = insn.op_str
            memory_str_index = memory_str.find('#') + 1
            memory_str = memory_str[memory_str_index:]
            memory = int(memory_str, 16)
        else:
            memory_reg = self.get_register(memory_reg_name)
            memory_disp = memory_operand.disp
            memory = memory_reg.value + memory_disp
        for j in range(0, len(insn.operands) - 1):
            operand = insn.operands[j]
            if operand.type == ARM64_OP_REG:
                reg_name = insn.reg_name(operand.reg)
                register = self.get_register(reg_name)

                if type(register) == Register:
                    if register in self.gen_regs:
                        context_register = 'gen_' + str(self.gen_regs.index(register))
                    else:
                        context_register = 'gen_' + insn.reg_name(operand.reg)
                else:
                    context_register = 'float_' + str(self.float_regs.index(register))
                self.context.str_memory(context_register, hex(memory + j * length))

                self.memory[hex(memory + j * length)] = register.value
                self.tracking['[' + str(memory + j * length) + ']'] = [reg_name]
                if self.store_notify is not None:
                    self.store_notify(hex(memory + j * length), register.value)

    def handle_store_pair(self, insn):
        self.handle_store_register(insn)

    def handle_add(self, insn):
        tracking = []
        if insn.operands[1].type == ARM64_OP_REG and insn.operands[2].type == ARM64_OP_REG:
            reg_name = insn.reg_name(insn.operands[1].reg)
            register = self.get_register(reg_name)
            if register.value < 0:  # 在取 ivar 的时候，会遇到这种问题，因为现在对于 SELF 指针的定义为一个负数的常量
                reg_name_2 = insn.reg_name(insn.operands[2].reg)
                register_2 = self.get_register(reg_name_2)
                dest = insn.operands[0]
                if dest.type == ARM64_OP_REG:
                    reg_name = insn.reg_name(dest.reg)
                    self.tracking[reg_name] = [reg_name_2]
                    register = self.get_register(reg_name)
                    register.value = register_2.value
                return

        result = 0
        for j in range(1, len(insn.operands)):
            operand = insn.operands[j]
            if operand.type == ARM64_OP_REG:
                reg_name = insn.reg_name(operand.reg)
                tracking.append(reg_name)
                register = self.get_register(reg_name)
                result += register.value
            elif operand.type == ARM64_OP_IMM:
                result += operand.imm
                tracking.append('#' + str(operand.imm))
        dest = insn.operands[0]
        if dest.type == ARM64_OP_REG:
            reg_name = insn.reg_name(dest.reg)
            self.tracking[reg_name] = tracking
            register = self.get_register(reg_name)
            # register.is_memory_content = False
            register.value = result

    def handle_sub(self, insn):
        tracking = []
        result = 0
        operand = insn.operands[1]
        if operand.type == ARM64_OP_REG:
            reg_name = insn.reg_name(operand.reg)
            tracking.append(reg_name)
            register = self.get_register(reg_name)
            result = register.value
        elif operand.type == ARM64_OP_IMM:
            tracking.append('#' + str(operand.imm))
            result = operand.imm
        for j in range(2, len(insn.operands)):
            operand = insn.operands[j]
            if operand.type == ARM64_OP_REG:
                reg_name = insn.reg_name(operand.reg)
                tracking.append(reg_name)
                register = self.get_register(reg_name)
                result -= register.value
            elif operand.type == ARM64_OP_IMM:
                tracking.append('#' + str(operand.imm))
                result -= operand.imm
        dest = insn.operands[0]
        if dest.type == ARM64_OP_REG:
            reg_name = insn.reg_name(dest.reg)
            self.tracking[reg_name] = tracking
            register = self.get_register(reg_name)
            register.value = result

    def handle_adrp(self, insn):
        value = insn.operands[1].imm
        reg_name = insn.reg_name(insn.operands[0].reg)
        register = self.get_register(reg_name)
        register.value = value
        if reg_name in self.tracking:
            del self.tracking[reg_name]
