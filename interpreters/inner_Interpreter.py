import ctypes

from capstone import *
from capstone.arm64 import *


class Register:

    def __init__(self, index):
        self.index = index
        self.low = ctypes.c_int32(0).value
        self.high = ctypes.c_int32(0).value
        self.is_memory_content = False

    def clear(self):
        self.low = ctypes.c_int32(0).value
        self.high = ctypes.c_int32(0).value
        self.is_memory_content = False

    @property
    def value(self):
        value = self.high << 32
        value += self.low
        return ctypes.c_int64(value).value

    @value.setter
    def value(self, value):
        self.high = value >> 32
        self.low = value & 0xffffffff


class Interpreter:

    def __init__(self):
        self.gen_regs = [Register(i) for i in range(31)]
        self.wzr = Register(-1)
        self.xzr = Register(-1)
        self.wsp = Register(-1)
        self.sp = Register(-1)
        self.pc = Register(-1)
        self.memory = {}

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
            elif insn.id == ARM64_INS_ADRP:
                self.handle_adrp(insn)
            elif (insn.id == ARM64_INS_LDR or
                  insn.id == ARM64_INS_LDRB or
                  insn.id == ARM64_INS_LDRSB or
                  insn.id == ARM64_INS_LDRH or
                  insn.id == ARM64_INS_LDRSH or
                  insn.id == ARM64_INS_LDRSW or
                  insn.id == ARM64_INS_LDUR or
                  insn.id == ARM64_INS_LDURB or
                  insn.id == ARM64_INS_LDURSB or
                  insn.id == ARM64_INS_LDURH or
                  insn.id == ARM64_INS_LDURSH or
                  insn.id == ARM64_INS_LDURSW):
                self.handle_load_register(insn)
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

            i += 1

    def get_register(self, name):
        if name == "sp":
            return self.sp
        if name.startswith("x"):
            reg_index = int(name[1:])
            return self.gen_regs[reg_index]
        else:
            print(name)

    def handle_move(self, insn):
        dest_register_name = insn.reg_name(insn.operands[0].reg)
        dest_register = self.get_register(dest_register_name)
        source_value = 0
        source = insn.operands[1]
        if source.type == ARM64_OP_IMM:
            source_value = source.imm
            dest_register.is_memory_content = False
        elif source.type == ARM64_OP_REG:
            source_register = self.get_register(insn.reg_name(source.reg))
            source_value = source_register.value
            dest_register.is_memory_content = source_register.is_memory_content
        dest_register.value = source_value

    def handle_load_register(self, insn):
        memory_operand = insn.operands[-1].mem
        memory_reg_name = insn.reg_name(memory_operand.base)
        memory_reg = self.get_register(memory_reg_name)
        memory_disp = memory_operand.disp
        memory = memory_reg.value + memory_disp
        for j in range(0, len(insn.operands) - 1):
            operand = insn.operands[j]
            if operand.type == ARM64_OP_REG:
                reg_name = insn.reg_name(operand.reg)
                register = self.get_register(reg_name)
                if hex(memory + j * 8) in self.memory:
                    memory_value = self.memory[hex(memory + j * 8)]
                    if type(memory_value) == str:
                        register.is_memory_content = True
                        register.value = int(memory_value[1:])
                    else:
                        register.is_memory_content = False
                        register.value = self.memory[hex(memory + j * 8)]
                else:
                    register.is_memory_content = True
                    register.value = memory + j * 8

    def handle_load_pair(self, insn):
        self.handle_load_register(insn)

    def handle_store_register(self, insn):
        memory_operand = insn.operands[-1].mem
        memory_reg_name = insn.reg_name(memory_operand.base)
        memory_reg = self.get_register(memory_reg_name)
        memory_disp = memory_operand.disp
        memory = memory_reg.value + memory_disp
        for j in range(0, len(insn.operands) - 1):
            operand = insn.operands[j]
            if operand.type == ARM64_OP_REG:
                reg_name = insn.reg_name(operand.reg)
                register = self.get_register(reg_name)
                if register.is_memory_content:
                    memory_value = "$" + str(register.value)
                    self.memory[hex(memory + j * 8)] = memory_value
                else:
                    self.memory[hex(memory + j * 8)] = register.value

    def handle_store_pair(self, insn):
        self.handle_store_register(insn)

    def handle_add(self, insn):
        result = 0
        for j in range(1, len(insn.operands)):
            operand = insn.operands[j]
            if operand.type == ARM64_OP_REG:
                reg_name = insn.reg_name(operand.reg)
                register = self.get_register(reg_name)
                result += register.value
            elif operand.type == ARM64_OP_IMM:
                result += operand.imm
        dest = insn.operands[0]
        if dest.type == ARM64_OP_REG:
            reg_name = insn.reg_name(dest.reg)
            register = self.get_register(reg_name)
            register.value = result

    def handle_sub(self, insn):
        result = 0
        operand = insn.operands[1]
        if operand.type == ARM64_OP_REG:
            reg_name = insn.reg_name(operand.reg)
            register = self.get_register(reg_name)
            result = register.value
        elif operand.type == ARM64_OP_IMM:
            result = operand.imm
        for j in range(2, len(insn.operands)):
            operand = insn.operands[j]
            if operand.type == ARM64_OP_REG:
                reg_name = insn.reg_name(operand.reg)
                register = self.get_register(reg_name)
                result -= register.value
            elif operand.type == ARM64_OP_IMM:
                result -= operand.imm
        dest = insn.operands[0]
        if dest.type == ARM64_OP_REG:
            reg_name = insn.reg_name(dest.reg)
            register = self.get_register(reg_name)
            register.value = result

    def handle_adrp(self, insn):
        value = insn.operands[1].imm
        reg_name = insn.reg_name(insn.operands[0].reg)
        register = self.get_register(reg_name)
        register.value = value