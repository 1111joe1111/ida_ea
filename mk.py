from pysideuic import compileUi


with open(r"./ui/elf.ui", "r") as r:
    with open("UI_out", "w") as w:
        compileUi(r, w)

quit()