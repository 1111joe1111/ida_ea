import pandas as pd
from pickle import load
import pandas.io.formats.format as pf

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

    # with open(r"TRACE!","rb") as r:
    # with open(r"orleans","rb") as r:

    with open(path,"rb") as r:
        df = load(r)
        df["name"] = df["name"].str.ljust(50)
        df = df.set_index(pd.DatetimeIndex(df["time"] * 1000000000).time)
        del df["time"]

        return df

pd.options.display.max_rows = 200
pd.options.display.width = 10000
pd.options.display.max_colwidth = 35
pd.options.display.max_columns = 10000
pf.IntArrayFormatter = IntArrayFormatter

