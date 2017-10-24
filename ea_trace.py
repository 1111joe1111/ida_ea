import time
from api_funcs import *
from ea_UI import Trace_UI, QtWidgets
from ea_utils import config, ea_warning, root_dir, save_config
from idaapi import *
from idc import *
from subprocess import Popen

try:
    import pandas as pd
    found_lib = True
except:
    found_lib = False


class Hook(DBG_Hooks):

    def __init__(self):
        DBG_Hooks.__init__(self)

    def dbg_process_exit(self, pid, tid, ea, exit_code):
        if isinstance(p_hooks, Hook) and dump_on_exit:
            dump()
        return 0

    def dbg_bpt(self, tid, ea):
        if get_bp(ea) == 9:
            if isinstance(p_hooks, Hook) and dump_on_break:
                dump()
        else:
            append(ea)
        return 0

    def dbg_trace(self, tid, ea):
        append(ea)
        return 0


def dump():
    global hooked
    global trace
    p_hooks.unhook()
    hooked = False
    df = pd.DataFrame(trace,columns=["time", "name"] + regs)
    df.set_index(pd.DatetimeIndex(df["time"]))
    dump_loc = config["trace_dir"] + ("/" if "/" in config["trace_dir"] else "\\") + str(int(time.time())) + ".pickle"
    df.to_pickle(dump_loc)
    ea_warning("Dumped IDA Trace to " + dump_loc,
               buttons=(("Open Folder", lambda: Popen("explorer " + config["trace_dir"], shell=True), False),
                ("Open In Console", lambda: open_in_console(dump_loc), False)),
               title="EA Trace")

    trace = []


def open_in_console(dump_loc):
    Popen('python "%s" "%s"' % (root_dir + "ea_read_t.py", dump_loc))


def append(ea):
    if ea not in names:
        names[ea] = GetDisasm(ea)
    trace.append([time.time(), names[ea]] + [get_rg(reg) for reg in regs])


def select_dir():

    config["trace_dir"] = QtWidgets.QFileDialog.getExistingDirectory()
    save_config()
    form.lineEdit.clear()
    form.lineEdit.insert(config["trace_dir"])


def select_dump():
    open_in_console(
        QtWidgets.QFileDialog.getOpenFileName(QtWidgets.QFileDialog(),
                                          'Open Dump', '',
                                          'pickle (*.pickle)')[0])


def go():

    global p_hooks
    global general
    global floating_point
    global dump_on_break
    global dump_on_exit

    if isinstance(p_hooks, Hook):
        p_hooks.unhook()

    general = form.checkBox.isChecked()
    floating_point = form.checkBox_2.isChecked()
    dump_on_break = form.radioButton.isChecked()
    dump_on_exit = form.radioButton_2.isChecked()
    p_hooks = Hook()
    p_hooks.hook()
    a.close()


def ea_trace():

    global a
    global form

    if found_lib:
        a = QtWidgets.QFrame()
        form = Trace_UI()
        form.setupUi(a)
        form.checkBox.click()
        form.radioButton_2.click()
        form.pushButton.clicked.connect(select_dir)
        form.pushButton_2.clicked.connect(go)
        form.pushButton_4.clicked.connect(select_dump)
        if config["trace_dir"]:
            form.lineEdit.insert(config["trace_dir"])
        # a.setWindowFlags(a.windowFlags() | QtCore.Qt.WindowStaysOnTopHint)
        a.show()
    else:
        ea_warning("Could not find Pandas in your Python distribution. Install it to use this feature")

trace = []
hooked = False
p_hooks = None
dump_on_exit = False
dump_on_break = False
general = False
floating_point = False
a = None
form = None
names = {}


