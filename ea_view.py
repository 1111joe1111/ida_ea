# -*- coding: utf-8 -*-
from idaapi import *
from idc import *
from idautils import *
from copy import copy
from time import sleep
from threading import Thread
from pickle import dump
from api_funcs import *
from ea_UI import View_UI
from ea_utils import QtGui, QtCore, get_mem_recursive, get_bits, parse_mem, cPrint, a_sync, config, save_config


class Hook(DBG_Hooks):

    def __init__(self, send):
        DBG_Hooks.__init__(self)
        self.send = send

    def dbg_bpt(self, tid, ea):
        if get_bp(ea) == 9:
            self.send()
        return 0

    def dbg_step_into(self):
        self.send()
        return 0

    def dbg_step_until_ret(self):
        self.send()
        return 0

    def dbg_step_over(self):
        self.send()
        return 0


def anchor_scrollbar():

    global scroll

    while view_open:
        if not scroll:
            sleep(0.005)
        else:
            for x in range(100):
                form.listWidget.verticalScrollBar().setValue(form.listWidget.verticalScrollBar().maximum())
                sleep(0.005)
            scroll = False


def deref_mem():

    results = [[], []]

    int_size = 4 if get_bits() else 8

    for i, reg in [(i, getattr(cpu, i)) for i in registers]:
        regions = []
        get_mem_recursive(reg, regions, int_size=int_size)
        results[0].append((i, regions))

    for i in range(0, config["stack_display_length"]):
        regions = []
        get_mem_recursive(cpu.rsp + (i*int_size), regions, int_size=int_size)
        results[1].append((i*int_size, regions))

    return results


def format_mem(results, append=True):

    global scroll

    regs, stack = results

    string = copy(style)
    string += "<div>"
    string += "".join((i + "&nbsp;"*(4-len(i)) + parse_mem(mem) + "\n") + "<br>" for i, mem in regs)
    string = string[:-4]
    string += "</div>"
    form.textEdit.clear()
    form.textEdit.insertHtml(string)

    string = copy(style)
    string += "<div>"
    string += "".join((cPrint("red", "RSP+%s&nbsp;" %  "{:03x}".format(i)) + parse_mem(mem)) + "<br>" for i, mem in stack)
    string += "</div>"
    form.textEdit_2.clear()
    form.textEdit_2.insertHtml(string)
    offset = GetFuncOffset(cpu.rip)

    if append:
        form.listWidget.addItem(offset if offset else hex(cpu.rip).replace("L", ""))
        scroll = True


def select_item(item):
    format_mem(states[form.listWidget.currentRow()], append=False)


def close(event):
    global view_open
    view_open = False
    clear()
    h.unhook()


def send():
    results = deref_mem()
    states.append(results)
    format_mem(results)
    form.listWidget.setCurrentRow(len(states) - 1)

def echo(num):
    print num


def clear():
    form.listWidget.clear()
    del states[:]


def dump_state():
    with open("./" + str(int(time.time())), "wb") as w:
        dump(states, w)


def rewind():

    regs, stack = states[form.listWidget.currentRow()]

    for i, v in regs:
        v = v[0][v[0].find(">0x") + 3:]
        v = int(v[:v.find("<")],16)
        print i, v
        set_rg(i,v)

    rsp = get_rg("RSP")
    stack_mem = ""

    for i, v in stack:
        v = v[0][v[0].find(">0x") + 3:]
        v = "".join(reversed(v[:v.find("<")].decode("HEX")))
        stack_mem += v

    dbg_write_memory(rsp, stack_mem)


def change_stack_length(x):
    print x
    config["stack_display_length"] = x
    save_config()


def ea_view():

    global h
    global form
    global a

    a = QtGui.QFrame()
    form = View_UI()
    form.setupUi(a)
    form.textEdit.setReadOnly(True)
    form.textEdit_2.setReadOnly(True)
    form.listWidget.itemClicked.connect(select_item)
    form.listWidget.itemClicked.connect(select_item)
    form.pushButton.clicked.connect(dump_state)
    form.pushButton_2.clicked.connect(clear)
    form.pushButton_3.clicked.connect(rewind)
    form.textEdit.setLineWrapMode(form.textEdit.NoWrap)
    form.textEdit_2.setLineWrapMode(form.textEdit.NoWrap)
    form.spinBox.valueChanged.connect(lambda x: change_stack_length(x))
    form.spinBox.setValue(config["stack_display_length"])
    a.closeEvent = close
    a.show()

    a_sync(anchor_scrollbar)

    h = Hook(send)
    h.hook()


registers = ("RAX", "RBX","RCX", "RDX","RDI", "RSI", "RSP", "RBP", "RIP",
             "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15")

style = (
    "<style> span{}\n "
    r"div{"
    "font-family:Hack;font-size:14px}\n"
    ".title{font-family:Ariel;font-size:14px;padding-top:1000px;}\n"
    ".blue{color:'#00FFFF'}"
    ".red{}"
    ".green{color:'#C4F0C5'}"
    ".yellow{color:'#737DFF'}"
    "</style>"
)

states = []
h = None
scroll = False
view_open = True
form = False
a = False
anchor_scrollbarr = False
