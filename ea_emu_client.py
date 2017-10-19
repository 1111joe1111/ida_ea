from idaapi import *
import socket
from pickle import loads, dumps
from threading import Thread
from os import system
from time import sleep
from api_funcs import *
from ea_UI import Emulate_UI
from PySide import QtGui, QtCore
from ea_utils import get_bits, root_dir, ea_warning

# Importing Unicorn Emulator directly into the IDAPython environment causes instability in IDA (random crashes ect.)
# As a result, Unicorn emulator is decoupled from IDA and runs as a seperate process communicating with IDA using a local socket (port 28745)
# The following client code runs within IDAPython and ships emulation requests to ea_emu_server which is a pure Python process

class Hook(DBG_Hooks):

    def __init__(self):
        DBG_Hooks.__init__(self)

    def dbg_bpt(self, tid, ea):
        send()
        return 0

    def dbg_step_into(self):
        send()
        return 0

    def dbg_step_until_ret(self):
        send()
        return 0

    def dbg_step_over(self):
        send()
        return 0


def send(addr=None, code=None):

    if get_process_state() != -1:
        ea_warning("Process must be paused/suspended")

    else:
        if not addr:
            addr = get_rg("RIP")
            code = dbg_read_memory(addr & 0xfffffffffffff000, 0x1000)

        flags = None
        bp = bpt_t()

        if get_bpt(addr,bp):
            flags = bp.flags
            bp.flags = 2
            update_bpt(bp)

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            s.connect((TCP_IP, TCP_PORT))
        except socket.error:
            launch_server()
            sleep(0.5)
            s.connect((TCP_IP, TCP_PORT))

        s.send(dumps(("emu", (addr,code, get_bits(), server_print))))
        error = False

        while True:
            data = s.recv(BUFFER_SIZE)
            if not data: break
            func, args = loads(data)

            if func == "result":
                break
            if func == "error":
                ea_warning(args)
                error = True
                break

            s.send(dumps(globals()[func](*args)))

        s.close()

        if flags:
            bp.flags = flags
            update_bpt(bp)

        if not error and annotate:

            rip = get_rg("RIP")

            if rip in args:
                del args[rip]

            for c, v in args.items():
                v = [i for i in v if i[0] not in ("rip", "eip")]
                comment = GetCommentEx(c, 0)

                if v:
                    annotation = " ".join(a + "=" + hex(b).replace("L", "") for a, b in v)
                    if comment and "e:" in comment:
                        comment = comment[:comment.find("e:")].strip(" ")
                    MakeComm(c, (comment if comment else "").ljust(10) + " e: " + annotation)
                else:

                    if comment and "e:" in comment:
                        comment = comment[:comment.find("e:")].strip(" ")

                    MakeComm(c, (comment if comment else "").ljust(10) + " e: " + "No reg changes")


def launch_server():

    # Launch emulation server as a seperate process (see top for details why)
    # Python subprocess module is broken in IDA so the os.system function is used instead
    # (This requires a new Thread because the os.system function blocks by default)

    global server_running

    Thread(target=system, args=("python \"%sea_emu_server.py\"" % root_dir,)).start()
    server_running = True



def ea_emulate():

    global form
    global a
    global server_running

    if not server_running:
        launch_server()

    a = QtGui.QFrame()
    form = Emulate_UI()
    form.setupUi(a)
    if hooked:
        form.checkBox.click()


    form.checkBox.stateChanged.connect(toggle_hooking)
    form.pushButton.clicked.connect(a.close)
    form.pushButton_2.clicked.connect(send)
    form.checkBox_3.stateChanged.connect(set_annotate)
    form.checkBox_2.stateChanged.connect(set_server_print)
    a.setWindowFlags(a.windowFlags() | QtCore.Qt.WindowStaysOnTopHint)


    a.show()


def toggle_hooking(state):

    global h
    global hooked

    if state:
        if not hooked:
            h = Hook()
            h.hook()
            hooked = True
    else:
        h.unhook()
        hooks = False


def set_annotate(state):
    global annotate
    annotate = True if state else False


def set_server_print(state):
    global server_print
    server_print = True if state else False


TCP_IP = '127.0.0.1';
TCP_PORT = 28745;
BUFFER_SIZE = 0x4000;
comments = []

file_name = None
h = None
hooked = False
form = None
a = None
server_running = False
annotate = True
server_print = True

