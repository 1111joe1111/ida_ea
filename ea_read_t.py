import pandas as pd
import pandas.io.formats.format as pf

from cPickle import load
from code import interact
from sys import argv

class IntArrayFormatter(pf.GenericArrayFormatter):
    def _format_strings(self):
        fmt_values = [
            '0x{:016x}'.format(x) for x in self.values
            ]

        return fmt_values


def read(file):
    with open(file, "r") as r:
        return r.read()


def filter_df(conditions):
    return pd.concat(conditions, axis=1).all(axis=1)



def load_df(path):

    with open(path,"rb") as r:
        df = load(r)
        df = df.set_index(pd.DatetimeIndex(df["time"] * 1000000000).time)
        del df["time"]
        return df

pd.options.display.max_rows = 200
pd.options.display.width = 10000
pd.options.display.max_colwidth = 20
pd.options.display.max_columns = 7
pf.IntArrayFormatter = IntArrayFormatter


if __name__ == "__main__":

    df = load_df(argv[1])
    print
    print df
    print
    print "dataframe name: df"
    print "dataframe columns: %s" % list(df.columns)
    print
    print "current settings:"
    print "pd.options.display.max_rows".ljust(50) + str(pd.options.display.max_rows)
    print "pd.options.display.width".ljust(50) + str(pd.options.display.width)
    print "pd.options.display.max_colwidth".ljust(50) + str(pd.options.display.max_colwidth)
    print "pd.options.display.max_columns".ljust(50) + str(pd.options.display.max_columns)
    print ""
    interact(local=globals())
