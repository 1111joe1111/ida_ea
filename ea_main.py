from ea_utils import QtGui, config
from ea_view import ea_view
from ea_heap import ea_heap
from ea_emu_client import ea_emulate
from ea_trace import ea_trace
from ea_skin import ea_reskin, apply_initial_skin
from ea_cmd import ea_cmd

if config["apply_skin_on_startup"]:
    apply_initial_skin()

menu_bar = next(i for i in QtGui.qApp.allWidgets() if isinstance(i, QtGui.QMenuBar))
menu = menu_bar.addMenu("IDA EA")
menu.addAction("Viewer").triggered.connect(ea_view)
menu.addAction("Heap").triggered.connect(ea_heap)
menu.addAction("Emulate").triggered.connect(ea_emulate)
menu.addAction("Trace Dump").triggered.connect(ea_trace)
menu.addAction("CMD").triggered.connect(ea_cmd)
menu.addAction("Reskin").triggered.connect(ea_reskin)
