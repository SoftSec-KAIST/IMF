# Copyright (c) 2017 HyungSeok Han and Sang Kil Cha at SoftSec, KAIST
#
# See the file LICENCE for copying permission.

import basic
import hook
import utils
import log
import const
import sys
import time
import argparse
import os
from multiprocessing import Pool
from model import Model
  
class ApiFuzz:
    def __init__(self):
        self.apis = {}
        self.apisets = {}
        self.apis= basic.load_apis()

    def load_apilog(self, log_fname, limit):
        with open(log_fname, 'rb') as f:
            data = f.read().split('\n')[:-1]
        if len(data) %2 !=0:
            data = data[:-1]
        idx = 0
        apilogs = []
        while idx < len(data) and idx < limit*2:
            if data[idx][:2] == 'IN':
                il = utils.evaluate(data[idx][2:])
            else:
                utils.error('load_apilog: parse IN error')

            if data[idx+1][:3] == 'OUT' :
                ol = utils.evaluate(data[idx+1][3:])
            else:
                utils.error('load_apilog: parse OUT error')
            apilog = log.ApiLog(self.apis[il[0]], il, ol)
            apilogs.append(apilog)
            idx+=2
        return apilogs

    def make_model(self, fnames, limit, path, core):
        apisets = utils.multiproc(self.load_apilog_multi(limit), fnames, core)
        model = Model(apisets)
        with open(path, 'wb') as f:
            code = model.fuzz(const.CODE_HEAD, const.CODE_TAIL)
            f.write(code)

    def load_apilog_multi(self, limit):
        def func(fname):
            apiseq = self.load_apilog(fname, limit)
            return apiseq
        return func

def show_help():
    print './gen-fuzz [filtered logs path] [output(fuzzer code) path] [# of core]'

def get_limit(logs):
    limit = None
    for log in logs:
        with open(log, 'rb') as f:
            n = (len(f.read().split('\n'))-1)/2
            if limit == None :
                limit = n
            elif limit != n:
                utils.error('Invalid triaged logs')
    return limit

if __name__== '__main__':
    if len(sys.argv) != 4:
        show_help()
        sys.exit(-1)
    fuzz = ApiFuzz()
    log_dir = sys.argv[1]
    logs = []
    for fname in os.listdir(log_dir):
        logs.append(os.path.join(log_dir, fname))
    limit = get_limit(logs)
    core = int(sys.argv[3])
    fuzz.make_model(logs, limit, sys.argv[2], core)

