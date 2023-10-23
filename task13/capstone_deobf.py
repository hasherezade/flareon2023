#!/usr/bin/env python3
import capstone
from capstone import *
import pefile
import binascii

g_offset_to_line = {}
g_jump_lookup = {}
g_curr_line = 0x1000
g_translate = False
g_out_file = None

def disasm_till_jump(md, binary_code, RVA, called_functions, targets, local_offsets):
    global g_curr_line
    global g_offset_to_line
    global g_translate
    global g_out_file
    global g_jump_lookup
    target = 0
    take_branch = False
    for insn in md.disasm(binary_code, RVA):

        is_branch = False
        is_uncond = False
        not_imm = False
        if capstone.x86.X86_GRP_JUMP in insn.groups:
            is_branch = True
            target = 0
            if (insn.operands[0].type != capstone.x86.X86_OP_IMM):
                not_imm = True
            else:
                target = insn.operands[0].value.imm # - code_section.VirtualAddress
                targets.add(target)

            if insn.mnemonic in [ "jmp" ]:
                is_uncond = True

        if is_uncond and target != 0 and not g_translate:
            g_jump_lookup[insn.address] = target
        if not is_uncond or (is_uncond and target in local_offsets) or not_imm:
            if not g_translate:
                curr_offset = g_curr_line
                g_offset_to_line[insn.address] = curr_offset
                g_curr_line += insn.size
                hex_string = binascii.hexlify(insn.bytes).decode('utf-8')
                print("0x%x -> 0x%x %s" % (insn.address, curr_offset, hex_string) )
            if g_translate:
                line = None
                mapped_offset = g_offset_to_line[insn.address]
                if (is_branch or insn.mnemonic == 'call') and (insn.operands[0].type == capstone.x86.X86_OP_IMM):
                    target_val = 0
                    try:
                        target_val = g_offset_to_line[insn.operands[0].value.imm]
                        line = ("%s\t0x%x" % (insn.mnemonic, target_val))
                    except KeyError:
                        #print("WARNING: key not found for the target")
                        try:
                            next_hop = g_jump_lookup[insn.operands[0].value.imm]
                            target_val = g_offset_to_line[next_hop]
                            line = ("%s\t0x%x" % (insn.mnemonic, target_val))
                        except KeyError:
                            print("WARNING: key not found for the target")
                if line is None:
                    line = ("%s\t%s" % (insn.mnemonic, insn.op_str))
                g_out_file.write("%d;%s" % (insn.size, line))
                g_out_file.write('\n')
                print("0x%x:\t%s" % (mapped_offset, line))

        if is_branch and not is_uncond:
            if (target in local_offsets):
                take_branch = False
        if is_branch and (take_branch or is_uncond):
            if not_imm:
                print(";Reg_call!")
                return (0, False)
            return (target, False)
        if insn.mnemonic == 'call':
            if (insn.operands[0].type == capstone.x86.X86_OP_IMM):
                called_function_address = insn.operands[0].value.imm
                called_functions.add(called_function_address)
            else:
                print(";call by NOT_IMM!")
        target = insn.address
        local_offsets.add(target)
        if capstone.x86.X86_GRP_RET in insn.groups:
            return (target, True)
    return (target, False)

def print_flow(md, code_section, target, img_base, called_functions, targets, local_offsets):

    is_ret = False
    while (not is_ret):
        #print ("Following target: %x " % target)
        if target in local_offsets:
            break
        if target == 0:
            break
        target_rva = target - img_base
        binary_code = code_section.get_data(target_rva, 0x5000)
        target, is_ret  = disasm_till_jump(md, binary_code, target, called_functions, targets, local_offsets)


def follow_targets(md, code_section, target, img_base, called_functions, targets, local_offsets, depth):
    targets2 = set()
    for t in targets:
        #sep = ">" * depth
        #print ("; %d %s Target: %x" % (depth, sep, t))
        print_flow(md, code_section, t, img_base, called_functions, targets2, local_offsets)
    return targets2
        
def print_function(md, code_section, RVA, img_base, called_functions):

    local_offsets = set()
    targets = set()
    target = RVA + img_base
    print(";Func: %x\n" % target)
    print_flow(md, code_section, target, img_base, called_functions, targets, local_offsets)
    
    depth = 1
    while (len(targets)):
        targets = follow_targets(md, code_section, target, img_base, called_functions, targets, local_offsets, depth)
        depth += 1

def print_function_and_called(md, code_section, RVA, img_base, all_called):
    if RVA in all_called:
        return
    all_called.add(RVA)
    called_functions = set()
    print_function(md, code_section, RVA, img_base, called_functions)
    print(";---\n")
    for addr in called_functions:
        addr = addr - img_base
        print_function_and_called(md, code_section, addr, img_base, all_called)

def disassemble(file_path):
    global g_translate
    global g_out_file
    
    pe = pefile.PE(file_path)
    eop = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    
    code_section = pe.get_section_by_rva(eop)
    code_dump = code_section.get_data()
    code_addr = pe.OPTIONAL_HEADER.ImageBase + code_section.VirtualAddress
    
    entrypoint_address = eop+pe.OPTIONAL_HEADER.ImageBase

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    
    VERIFICATION_RVA = 0x1a3d4
    start = eop
    thread1_start = 0x4928c
    thread2_start = 0x4e0e7 
    addresses = [eop, thread1_start, thread2_start]

    all_called = set()
    for start in addresses:
        print_function_and_called(md, code_section, start, pe.OPTIONAL_HEADER.ImageBase, all_called)

    g_out_file = open("yoda.asm", "w")
    g_translate = True
    all_called.clear()
    for start in addresses:
        print_function_and_called(md, code_section, start, pe.OPTIONAL_HEADER.ImageBase, all_called)

disassemble("y0da.exe")

