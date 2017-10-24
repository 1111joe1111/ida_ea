from pysideuic import compileUi


with open(r"./restyle.ui", "r") as r:
    with open("out.ui_out", "w") as w:
        compileUi(r, w)

quit()