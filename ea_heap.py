from idaapi import *
from idautils import *
from idc import *
from api_funcs import *
from collections import namedtuple
from re import findall
from time import time
from copy import copy
import sys
from PySide import QtCore, QtGui
from ea_UI import Heap_UI, Set_Offset_UI, ELF_Only_UI
from ea_utils import read, root_dir, config, get_bits, save_config


class Hook(DBG_Hooks):

    def __init__(self):
        DBG_Hooks.__init__(self)

    def dbg_bpt(self, tid, bptea):

        if bptea == malloc_addr:
            addr = get_rg("RAX") - int_size*2
            c = chunk(*(to_list(dbg_read_memory(addr, 6 * int_size)) + [addr]))
            addr = hex(addr).replace("L", "")

            if not form.listWidget_4.findItems(addr, QtCore.Qt.MatchFlag.MatchExactly):
                form.listWidget_4.addItem(addr)

            chunkmap_2[addr] = c
            update_chunk(c)
            get_malloc_state()

        return 0


class field():

    def __init__(self,val,size):
        self.val = val
        self.size = size


class malloc_state():

    def __init__(self, address):
        self.mutex = field(0, 0.5 if int_size == 8 else 1)
        self.flags = field(0, 0.5 if int_size == 8 else 1)
        self.fastbinsY = field([1],10)
        self.top = field(0,1)
        self.last_remainder = field(0,1)
        self.bins = field([1], 254)
        self.binmap = field([0.5], 4)
        self.next = field(0,1)
        self.next_free = field(0,1)
        self.attached_threads = field(0,1)
        self.system_mem = field(0,1)
        self.max_system_mem = field(0,1)

        # Not a member of glibc malloc_state
        self.address = address


class chunk():

    def __init__(self, prev_size, size, fd, bk, fd_nextsize, bk_nextsize, address):
        self.prev_size = prev_size
        self.size = size & 0xfffffffc
        self.fd = fd
        self.bk = bk
        self.fd_nextsize =fd_nextsize
        self.bk_nextsize = bk_nextsize
        self.prev_in_use = size & 0x1
        self.is_mmapped = 1 if size & 0x2 else 0

        # Not a member of glibc chunk
        self.data = ""
        self.address = address

    def __str__(self):

        a = ("prev_size" ,"size" ,"fd",  "bk", "fd_nextsize", "bk_nextsize")

        return ( "Chunk @ " + hex(getattr(self, "address")) + " = {\n" +
                 "".join( "    " + i + " = " + hex(getattr(self, i)) + "\n" for i in a) + "\n" +
                 "    prev_in_use = " + ("True" if self.prev_in_use else "False") + "\n"
                 "    is_mmapped = "  + ("True" if self.is_mmapped else "False")  + "\n"
                 + "}")


def to_hex(x):
    return hex(x).replace("L","")


def to_list(x, chunk_size = 8):
    return [ to_int(x[i:i+chunk_size]) for i in range(0, len(x), chunk_size) ]


def to_int(x):

    a = "".join(reversed(x)).encode("HEX")
    if len(a) % 2:
        a = "0" + a

    return int(a, 16)


def update_chunk(c):

    next_chunk = dbg_read_memory(c.address, 6 * int_size)

    if next_chunk:
        c = chunk(*(to_list(next_chunk) + [c.address]))
        c.data = dbg_read_memory(c.address + 2 * int_size, min(c.size, 0x500)).encode("HEX")

        if c.data:
            c.data = " ".join(c.data[i:i + 2] for i in range(0, len(c.data), 2))
        else:
            c.data = ""

        return c


def fill_field(malloc_state, field, mem, current, list=False):


    field_size = getattr(malloc_state,field).size

    if list:
        var_size = getattr(malloc_state,field).val.pop()
        setattr(malloc_state, field, to_list(mem[current:int(current + int_size * var_size * field_size)], int(int_size*var_size)))
    else:
        var_size = 1
        setattr(malloc_state, field, to_int(mem[current:int(current + int_size * field_size)]))

    current += int(int_size * field_size * var_size)

    return current


def get_malloc_state():

    main_arena = malloc_state(main_arena_addr)
    mem = dbg_read_memory(main_arena.address, 2200)
    current = 0
    fields = ["mutex", "flags", "fastbinsY", "top", "last_remainder", "bins",
              "binmap", "next", "next_free", "attached_threads", "system_mem", "max_system_mem"]

    for field in fields:
        current = fill_field(main_arena, field, mem, current,
                             True if isinstance(getattr(main_arena, field).val, list) else False)

    main_arena.fastbinsY = [[item] for item in main_arena.fastbinsY]
    main_arena.bins = [[item] for item in main_arena.bins]
    form.listWidget.clear()
    form.listWidget_3.clear()

    for n, bin in enumerate(main_arena.fastbinsY):
        if bin and bin[0]:
            get_chunks(bin, main_arena.address)
            if bin:
                name = "Fastbin %s" % hex(n)
                form.listWidget.addItem(name)
                binmap[name] = bin
        elif bin:
            bin.pop()

    for n, bin in enumerate(main_arena.bins):
        if bin and not (main_arena.address < bin[0] < main_arena.address + 2200):
            get_chunks(bin, main_arena.address)
            if bin:
                name = "Bin %s" % hex(n)
                form.listWidget_3.addItem(name)
                binmap[name] = bin
        elif bin:
            bin.pop()


def get_chunks(bin, state_addr):

    next_chunk = True
    chunks = []
    addr = bin.pop()

    while next_chunk:
        next_chunk = dbg_read_memory(addr, 6 * int_size)

        if next_chunk:
            c = chunk(*(to_list(next_chunk) + [addr]))
            bin.append(c)
            chunks.append(c.fd)
            c.data = dbg_read_memory(addr + 2 * int_size, min(c.size, 0x500)).encode("HEX")
            c.data = " ".join(c.data[i:i+2] for i in range(0, len(c.data), 2))
            if state_addr < c.fd < state_addr + 2200:
                break

            addr = c.fd
        else:
            break


def get_main_arena():

    global base_addr

    for addr in Segments():
        if findall("libc_.*\.so",SegName(addr)):
            seg = getseg(addr)

            if seg.perm | SEGPERM_EXEC == seg.perm:
                return addr


def select_bin(item):

    global chunkmap

    form.listWidget_2.clear()
    for chunk in binmap[item.text()]:
        form.listWidget_2.addItem(hex(chunk.address))
        chunkmap[hex(chunk.address).replace("L", "")] = chunk


def select_chunk(item, chunkmap):

    chunk = chunkmap[item.text()] = update_chunk(chunkmap[item.text()])
    form.textEdit.clear()
    form.textEdit.insertHtml("<style>p{font-family:Hack;font-size:14px}</style>" + "<p>" + chunk.data + "</p>")

    string = (chunk_template) % (
        to_hex(chunk.address),
        to_hex(chunk.prev_size),
        to_hex(chunk.size),
        to_hex(chunk.fd),
        to_hex(chunk.bk),
        to_hex(chunk.fd_nextsize),
        to_hex(chunk.bk_nextsize),
        "True" if chunk.prev_in_use else "False",
        "True" if chunk.is_mmapped else "False"
    )

    form.textEdit_2.clear()
    form.textEdit_2.insertHtml(string)


def set_config():

    global b

    b = QtGui.QWidget()
    form = Set_Offset_UI()
    form.setupUi(b)
    b.show()

    form.pushButton.clicked.connect(lambda: get_text(form))


def get_text(form):

    global malloc_offset
    global main_arena_offset

    offsets = [form.lineEdit.text(), form.lineEdit_2.text(), form.lineEdit_3.text(), form.lineEdit_4.text()]

    for x in range(4):
        if offsets[x][:2] == "0x":
            offsets[x] = int(offsets[x][2:], 16)
        else:
            offsets[x] = int(offsets[x])

    config["libc_offsets"] = offsets
    main_arena_offset, malloc_offset = offsets[:2] if int_size == 8 else offsets[2:]
    b.close()
    save_config()
    ea_heap()


def ea_heap():

    global form
    global a
    global ELF_only
    global item_no
    global hook
    global main_arena_addr
    global malloc_addr

    if "ELF" not in idaapi.get_file_type_name():
        a = QtGui.QWidget()
        form = ELF_Only_UI()
        form.setupUi(a)
        a.show()
        form.pushButton.clicked.connect(a.close)
    else:
        if main_arena_offset == 0  and malloc_offset == 0:
            set_config()
        else:
            base_addr = get_main_arena()
            malloc_addr = base_addr + malloc_offset
            main_arena_addr = base_addr + main_arena_offset

            a = QtGui.QWidget()
            form = Heap_UI()
            form.setupUi(a)
            form.textEdit.setReadOnly(True)
            form.textEdit_2.setReadOnly(True)
            a.show()
            hook = Hook()
            hook.hook()
            a.closeEvent = lambda x: hook.unhook()
            form.listWidget.itemClicked.connect(select_bin)
            form.listWidget_3.itemClicked.connect(select_bin)
            form.listWidget_2.itemClicked.connect(lambda x: select_chunk(x, chunkmap))
            form.listWidget_4.itemClicked.connect(lambda x: select_chunk(x, chunkmap_2))
            # form.checkBox.stateChanged.connect(lambda x: (
            #     add_bp(malloc_addr, 10), hook.hook()) if x else (add_bp(malloc_addr, 2), hook.unhook()))
            get_malloc_state()


chunk_template = read(root_dir + "chunk_template.html")
int_size =  4 if get_bits() else 8

main_arena_offset, malloc_offset = config["libc_offsets"][:2] if int_size == 4 else config["libc_offsets"][2:]

chunkmap = {}
chunkmap_2 = {}
binmap = {}

form = None
a = None
b = None
hook = None
base_addr = None
main_arena_addr = None
malloc_addr = None
