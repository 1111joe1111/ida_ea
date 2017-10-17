# -*- coding: utf-8 -*-

from idaapi import *
from idc import *
from idautils import *
from PySide.QtCore import *
from PySide.QtGui import *
from copy import copy
from PySide import QtCore, QtGui
from ea_utils import get_mem_recursive, parse_mem, get_bits
from ea_UI import Cmd_UI


def get(addr, int_size, n=20):

    string = copy(style)
    string += "<p>"

    for x in range(n):
        regions = []
        get_mem_recursive(addr + x * 4, regions, int_size=int_size)
        string += parse_mem(regions) + "<br>"

    string += "</p>"

    form.textEdit.append(string)
    form.textEdit.verticalScrollBar().setValue(form.textEdit.verticalScrollBar().maximum())


def find(arg, int_size):

    matches = []
    addr = 0

    for x in range(100):

        newAddr = FindText(addr, SEARCH_DOWN, 0, 0, arg)
        print hex(newAddr)
        print hex(addr), hex(newAddr)
        if newAddr != 0xffffffffffffffffL:
            if newAddr > addr:
                addr = newAddr
                matches.append(addr)
            else:
                addr += 0x4
        else:
            break

    string = copy(style)
    string += "<p>"

    for addr in matches:
        regions = []
        get_mem_recursive(addr, regions, int_size=int_size)
        string += parse_mem(regions) + "<br>"

    string += "</p>"

    form.textEdit.append(string)
    form.textEdit.verticalScrollBar().setValue(form.textEdit.verticalScrollBar().maximum())


def do_cmd():

    int_size = 4 if get_bits() else 8
    cmd = form.lineEdit.text()
    form.textEdit.append(copy(style) + "<span>&#x25B6; " + cmd +"</span><br>")
    cmd = [i for i in cmd.split(" ") if i]

    if cmd[0][0] == "x":
        length = to_int(cmd[0][1:])
        addr = to_int(cmd[1])
        get(addr, int_size, length)

    elif cmd[0] == "searchmem":
        print cmd[1]

        if cmd[1][0] == "\"" and cmd[1][-1] == "\"":
            cmd[1] = cmd[1][1:-1]

        find(str(cmd[1]), int_size)


def to_int(i):

    if "0x" in i or "0X" in i:
        return int(i[2:],16)
    else:
        return int(i)


def ea_cmd():

    global a
    global form

    a = QFrame()
    form = Cmd_UI()
    form.setupUi(a)
    form.textEdit.setReadOnly(True)
    form.lineEdit.returnPressed.connect(do_cmd)
    form.pushButton.clicked.connect(do_cmd)
    # a.setWindowFlags(a.windowFlags() | Qt.WindowStaysOnTopHint)
    a.show()


addresses = 0
max_iterations = 10
iterations = 0
a = None
form = None

style = (
    "<style> span{color:white;}\n "
    r"p, span{font-family:Hack;font-size:14px;}"
    ".title{font-family:Ariel;font-size:14px;padding-top:1000px;}\n"
    ".blue{color:'#00FFFF'}"
    ".red{color:'white'}"
    ".green{color:'#C4F0C5'}"
    ".yellow{color:'#737DFF'}"
    ".yellow{color:'#737DFF'}"
    "</style>"
)
