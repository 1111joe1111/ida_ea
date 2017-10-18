#!/usr/bin/env python

from collections import OrderedDict
from copy import copy
import socket
from pickle import dumps, loads
from traceback import format_tb
import sys

try:
    from unicorn import *
    from unicorn.x86_const import *
    found_unicorn = True
except:
    found_unicorn = False

try:
    from capstone import *
    found_capstone = True
except:
    found_capstone = False


def debug(type, value, traceback):
    print "".join(format_tb(traceback, None))
    print type
    print value
    raw_input()


def get(func, args):
    conn.send(dumps((func, args)))
    data = loads(conn.recv(BUFFER_SIZE))
    return data


def mem_to_int(val):
    return int("".join(list(reversed(val))).encode("HEX"),16)


def lookup_reg(target, uc):
    return uc.reg_read(reg_total[target]) if target in reg_total else eval(target)


def dbg_read_memory(mem, size):
    return get("dbg_read_memory", (mem, size))


def get_rg(rg):
    return get("get_rg", (rg,))


def get_mem(addr, uc):

    size = 0x1000
    rounded = addr & 0xfffffffffffff000
    uc.mem_map(rounded, size)

    while True:
        mem = dbg_read_memory(rounded, size)
        size -= 0x10
        if mem:
            break
        if not size:
            return 0

    mapped_mem[rounded] = size
    uc.mem_write(rounded, mem)

    return 1


def hook_code(uc, address, size, user_data):

    global last
    global reg_state

    new_reg_state = get_state(uc)

    reg_changes = [(i, new_reg_state[i]) for i in new_reg_state if new_reg_state[i] != reg_state[i]]

    if last not in annotations:
        annotations[last] = reg_changes

    reg_state = new_reg_state

    if server_print:
        if address in instructions:
            print (hex(address) + ": " + " ".join(instructions[address])).ljust(50) + "".join("%s: %s; "%(a,hex(b)) for a, b in reg_changes)
        elif dbg:
            print "Unmapped instruction %s" % address

    if address == 0:
        uc.emu_stop()

    last = address


def hook_err(uc, access, address, size, value, user_data, real=False):

    rounded = address & 0xfffffffffffff000
    size = 0x1000

    if access == UC_MEM_WRITE_UNMAPPED:
        uc.mem_map(rounded, size)
        return True

    elif access == UC_MEM_READ_UNMAPPED:
        if get_mem(address, uc):
            return True

    return False


def get_state(uc):
    return {name: uc.reg_read(reg) for name, reg in x86_regs.items() if name != "rip"}


def emulate(address=False, code=False, _32_bits=True):

    if found_capstone and found_unicorn:

        global instructions
        global reg_state
        global last
        global annotations

        annotations = {}

        registers = (("EAX", "EBX", "ECX", "EDX", "EDI", "ESI", "ESP", "EBP", "EIP")
                     if _32_bits else
                     ("RAX", "RBX", "RCX", "RDX", "RDI", "RSI", "RSP", "RBP", "RIP",
                      "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"))

        reg_vals = {r: get_rg(r) for r in registers}

        if not address:
            address = reg_vals["EIP" if _32_bits else "RIP"]
        if not code:
            code = dbg_read_memory(address, 200)

        address = int(address)
        rounded = address & 0xfffffffffffff000
        last = address
        md = Cs(CS_ARCH_X86, CS_MODE_32 if _32_bits else CS_MODE_64)
        instructions = OrderedDict((i.address, (i.mnemonic, i.op_str)) for i in md.disasm(code[address - rounded:], address))

        if dbg:
            print reg_vals
            print instructions

        uc = Uc(UC_ARCH_X86, UC_MODE_32 if _32_bits else UC_MODE_64)
        uc.mem_map(rounded, 0x1000)
        uc.mem_write(rounded, code)

        reg_dict = x86_regs if _32_bits else x64_regs

        for name, reg in reg_dict.items():
            if name.upper() in reg_vals:
                uc.reg_write(reg, reg_vals[name.upper()])

        uc.reg_write(reg_dict["eip" if _32_bits else "rip"], address)
        uc.hook_add(UC_HOOK_CODE, hook_code)
        uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, hook_err)

        reg_state = get_state(uc)

        try:
            uc.emu_start(address, address + 200, timeout=1000000)
        except UcError as e:
            if dbg:
                print e
                # raw_input()

        return "result", annotations

    else:
        found_neither = True if not found_unicorn and not found_capstone else False
        error = ("Could not find " +
                 ("Capstone or Unicorn" if found_neither else "Capstone" if not found_capstone else "Unicorn") +
                 " in your Python Library, Please install " + ("them" if found_neither else "it") +
                 " to enable emulation")
        return "error", error


def server():

    global conn
    global server_print
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((TCP_IP, TCP_PORT))
    s.listen(1)

    while True:
        conn, addr = s.accept()
        res = conn.recv(0x5000)
        emu, (addr, code, bits, server_print) = loads(res)

        if emu != "emu": break
        conn.send(dumps(emulate(addr, code, bits)))
        conn.close()


sys.excepthook = debug
TCP_IP = '127.0.0.1'
TCP_PORT = 28745
BUFFER_SIZE = 0x5000

annotations = {}
mapped_mem = {}
reg_state = None
instructions = False
conn = None
registers = None

x86_regs = dict([('eax', UC_X86_REG_EAX), ('ebx', UC_X86_REG_EBX),
                 ('ecx', UC_X86_REG_ECX), ('edx', UC_X86_REG_EDX),
                 ('esi', UC_X86_REG_ESI), ('edi', UC_X86_REG_EDI),
                 ('esp', UC_X86_REG_ESP), ('ebp', UC_X86_REG_EBP),
                 ('eip', UC_X86_REG_EIP)])

x64_regs = dict([('rax', UC_X86_REG_RAX), ('rbx', UC_X86_REG_RBX),
                 ('rcx', UC_X86_REG_RCX), ('rdx', UC_X86_REG_RDX),
                 ('rsi', UC_X86_REG_RSI), ('rdi', UC_X86_REG_RDI),
                 ('rsp', UC_X86_REG_RSP), ('rbp', UC_X86_REG_RBP),
                 ('r8', UC_X86_REG_R8), ('r9', UC_X86_REG_R9),
                 ('r10', UC_X86_REG_R10), ('r11', UC_X86_REG_R11),
                 ('r12', UC_X86_REG_R12), ('r13', UC_X86_REG_R13),
                 ('r14', UC_X86_REG_R14), ('r15', UC_X86_REG_R15),
                 ('rip', UC_X86_REG_RIP)
                 ])

reg_total = copy(x64_regs)
reg_total.update(x86_regs)

dbg = False
server_print = True

print "Running emulation server..."

server()
