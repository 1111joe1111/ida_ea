from idaapi import *
from idc import *
from idautils import *
from threading import Thread


def add_bp(addr, flags=9, type=4, size=0):
    add_bpt(addr,size,type)
    bp = bpt_t()
    get_bpt(addr,bp)
    bp.flags = flags
    bp.type = type
    bp.size = size
    update_bpt(bp)
    return bp


def get_bp(addr, ret_flags=True):
    bp = bpt_t()
    get_bpt(addr,bp)
    return bp.flags if ret_flags else bp


def set_trace(start, end):
    add_bp(start,104)
    add_bp(end, 72)


def runDebugger(file, args=None):

    print file

    if not args:
        StartDebugger(file,file, file[:max(file.rfind("/"), file.rfind("\\"))])
    else:
        StartDebugger(file," ".join([file] + args), file[:max(file.rfind("/"), file.rfind("\\"))])


def get_rg(reg):
    get_reg_val(reg, reg_mem)
    return reg_mem.ival


def set_rg(reg, val):
    reg_mem.ival = val
    set_reg_val(reg, reg_mem)


def set_grp_flags(name, flag, type=4, size=0):
    a = bpt_vec_t()
    get_grp_bpts(a, name)

    for bp in a:
        add_bp(bp.ea, flag, type, size)


def add_grp(name, l, flags=9, type=4, size=0):
    for i in l:
        set_bpt_group(add_bp(i, flags, type, size), name)


def disas(start,end):

    result = []
    i = start
    while i < end:
        result.append((i,GetDisasm(i)))
        i += ItemSize(i)

    return result


def find_ins(ins, i, limit=1000):

    rd = ""

    for x in range(limit):
        i += ItemSize(i)
        if ins in GetDisasm(i):
            break
    else:
        i = 0

    return i


def brk_write(start, end, name="brk_read"):

    for addr, i in disas(start, end):
        target = i.split(",")[0]

        if "[" in target:
            set_bpt_group(add_bp(addr), name)


def brk_read(start, end, name="brk_read"):

    for addr, i in disas(start, end):
        target = i.split(",")

        if len(target) > 1:
            if "[" in target[1]:
                set_bpt_group(add_bp(addr), name)


def traceFunc(filter ="", type= 10):

    for func in Functions(0, 0xffffffff):
        name = GetFunctionName(func)

        if filter in name.lower():
            print name
            add_bp(func, type)


def traceSeg(filter =""):

    global hooked

    if not hooked:
        p_hooks.hook()

    for addr in Segments():
        name = SegName(addr)
        end = SegEnd(addr)

        if filter in name.lower():
            print name
            add_bp(addr, 10, end - addr)


def rd_int(addr=None, reg=None, size=4):
    addr = get_rg(reg) if reg else addr
    a = dbg_read_memory(addr, size)
    return int("".join(reversed(list(a))).encode("HEX"), 16) if a else 0


def nop(ea):
    for x in range(ItemSize(ea)):
        patch_byte(ea + x, 0x90)


regs = ["RIP", "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RSP", "RBP",
        "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"]

reg_mem = regval_t()




