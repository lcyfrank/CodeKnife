from capstone import *
from capstone.arm import *
from capstone.arm64 import *

# code = b"\xf1\x02\x03\x0e\x00\x00\xa0\xe3\x02\x30\xc1\xe7\x00\x00\x53\xe3"
code = b"\x00\x00\x00\x94"

# hardware architecture and hardware mode
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

# code and the address of first instruction
for i in md.disasm(code, 0x1000):
    # the fields of `CsInsn` are followed:
    # > id: Integer, Instruction ID of the instruction
    # > address: Integer, Address of the instruction
    # > mnemonic: String, Mnemonic of the instruction
    # > op_str: String, Operands of the instruction
    # > size: Integer, The size of the instruction which is expressed in number of bytes
    # > bytes: Array, The byte sequence of the instruction which the `size` is the length
    #   of this array

    # We just care the instruction `bl` or `cmp`
    # if i.id in (ARM_INS_BL, ARM_INS_CMP):
    print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

        # regs_read: Array, The implicit registers read
        # if len(i.regs_read) > 0:
        #     print("\tImplicit registers read: ", end = '')
        #     for r in i.regs_read:
        #         print("%s " % i.reg_name(r))
        #     print

        # groups: Array, The groups this instruction belongs to
        # if len(i.groups) > 0:
        #     print("\tThis instruction belongs to groups: ", end = ''),
        #     for g in i.groups:
        #         print("%u" %g),
        #     print

# code = b"\xe1\x0b\x40\xb9\x20\x04\x81\xda\x20\x08\x02\x8b"

# md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
# md.detail = True
            
# for insn in md.disasm(code, 0x38):
#     print("0x%x:\t%s\t%s" %(insn.address, insn.mnemonic, insn.op_str))

#     # operands: Array, The operands of this instruction
#     if len(insn.operands) > 0:
#         print("\tNumber of operands: %u" %len(insn.operands))
#         c = -1
#         for i in insn.operands:
#             c += 1
#             if i.type == ARM64_OP_REG:  # Register
#                 print("\t\toperands[%u].type: REG = %s" %(c, insn.reg_name(i.value.reg)))
#             if i.type == ARM64_OP_IMM:  # Number
#                 print("\t\toperands[%u].type: IMM = 0x%x" %(c, i.value.imm))
#             if i.type == ARM64_OP_CIMM: 
#                 print("\t\toperands[%u].type: C-IMM = %u" %(c, i.value.imm))
#             if i.type == ARM64_OP_FP:   # Real Number
#                 print("\t\toperands[%u].type: FP = %f" %(c, i.value.fp))
#             if i.type == ARM64_OP_MEM:  # Memory
#                 print("\t\toperands[%u].type: MEM" %c)
#                 if i.value.mem.base != 0:
#                     print("\t\t\toperands[%u].mem.base: REG = %s" \
#                         %(c, insn.reg_name(i.value.mem.base)))
#                 if i.value.mem.index != 0:
#                     print("\t\t\toperands[%u].mem.index: REG = %s" \
#                         %(c, insn.reg_name(i.value.mem.index)))
#                 if i.value.mem.disp != 0:
#                     print("\t\t\toperands[%u].mem.disp: 0x%x" \
#                         %(c, i.value.mem.disp))
#             if i.shift.type != ARM64_SFT_INVALID and i.shift.value:
# 	            print("\t\t\tShift: type = %u, value = %u" \
#                     %(i.shift.type, i.shift.value))

#             if i.ext != ARM64_EXT_INVALID:
# 	            print("\t\t\tExt: %u" %i.ext)

#     if insn.writeback:  # If this instruction write value back
#         print("\tWrite-back: True")
#     if not insn.cc in [ARM64_CC_AL, ARM64_CC_INVALID]:  # The condition of this instruction
#         print("\tCode condition: %u" %insn.cc)
#     if insn.update_flags:  # If this instruction update the flags
#         print("\tUpdate-flags: True")


# # If we just want to get `address`, `size`, `mnemonic`, `op_str`
# # we can use the lighter API:
# for (address, size, mnemonic, op_str) in md.disasm_lite(code, 0x1000):
#     print("0x%x:\t%s\t%s" %(address, mnemonic, op_str))