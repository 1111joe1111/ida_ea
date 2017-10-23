from ea_UI import QtGui, QtWidgets, Name_UI, Reskin_UI
from ea_utils import config, root_dir, save_config
from idaapi import *


def color_selected(i, color):
    back = "{:04x}".format(color.rgb())[2:]
    buttons[i][0].setStyleSheet("background: " + "#" + back)
    buttons[i][2] = back


def select_color(i):

    global color
    color = QtWidgets.QColorDialog()
    color.setCustomColor(0, 0x212121)
    color.setCurrentColor(QtGui.QColor.fromRgb(int(buttons[i][0].styleSheet().split("#")[1], 16)))
    color.colorSelected.connect(lambda color: color_selected(i, color))
    color.open()


def save_preset():

    global name_ui
    name_ui = QtWidgets.QFrame()
    form_2 = Name_UI()
    form_2.setupUi(name_ui)
    name_ui.show()
    form_2.pushButton.clicked.connect(lambda: save_preset_2(form_2, name_ui))


def save_preset_2(form_2, name_ui):

    name = form_2.lineEdit.text()
    form.comboBox.addItem(name)
    config["skins"].append([name] + [item[2] for item in buttons])
    save_config()
    form.comboBox.setCurrentIndex(len(config["skins"] )- 1)
    name_ui.close()


def changed(i):

    for i, v in enumerate(config["skins"][i][1:]):
        buttons[i][0].setStyleSheet("background: " + "#" + v)
        buttons[i][2] = v


def apply_skin():

    with open(root_dir + "style_template.css", "r") as r:
        style = r.read()

    for i, c in enumerate(item[2] for item in buttons):
        style = style.replace("{%s}" % (i), "#" + c)

    config["current_skin"] = [item[2] for item in buttons]
    save_config()

    QtWidgets.qApp.setStyleSheet(QtWidgets.qApp.styleSheet().split("/*IDA EA START*/")[0] + style)



def apply_initial_skin():

    if config["current_skin"]:
        with open(root_dir + "style_template.css", "r") as r:
            style = r.read()

        print config["current_skin"]

        for i, c in enumerate(item for item in config["current_skin"]):
            style = style.replace("{%s}" % (i), "#" + c)

        QtWidgets.qApp.setStyleSheet(QtWidgets.qApp.styleSheet().split("/*IDA EA START*/")[0] + style)


def toggle_apply_onstartup(state):
    config["apply_skin_on_startup"] = True if state else False
    save_config()


def ea_reskin():

    global a
    global form
    global buttons

    a = QtWidgets.QFrame()
    form = Reskin_UI()
    form.setupUi(a)
    a.show()

    for i in config["skins"]:
        form.comboBox.addItem(i[0])

    form.comboBox.activated.connect(changed)

    buttons = [
        [form.pushButton, form.pushButton_2,     None],
        [form.pushButton_23, form.pushButton_24, None],
        [form.pushButton_25, form.pushButton_26, None],
        [form.pushButton_9, form.pushButton_10,  None],
        [form.pushButton_13, form.pushButton_14, None],
        [form.pushButton_27, form.pushButton_28, None],
        [form.pushButton_21, form.pushButton_22, None],
        [form.pushButton_15, form.pushButton_16, None],
        [form.pushButton_11, form.pushButton_12, None]
    ]

    for x in range(len(buttons)):
        buttons[x][0].clicked.connect(lambda x=x: select_color(x))
        buttons[x][1].clicked.connect(lambda x=x: select_color(x))

    form.pushButton_18.clicked.connect(save_preset)
    form.pushButton_17.clicked.connect(lambda: process_ui_action("SetColors"))
    form.pushButton_20.clicked.connect(apply_skin)
    form.checkBox.stateChanged.connect(lambda x: toggle_apply_onstartup(x))

    changed(0)

a = None
form = None
buttons = None
name_ui = None
color = None
