# Copyright (c) 2017 HyungSeok Han and Sang Kil Cha at SoftSec, KAIST
#
# See the file LICENCE for copying permission.

import const
import sys
from multiprocessing import Pool

def evaluate(s):
    try:
        return eval(s)
    except:
        error('evalutate error :%s'%s )

def error(s):
    print(s)
    if const.DEBUG :
        sys.exit(-1)

def multiproc(func, l, core = 4):
    pool = Pool(core)
    ret = pool.map(func, l)
    pool.terminate()
    return ret
