# Copyright (c) 2017 HyungSeok Han and Sang Kil Cha at SoftSec, KAIST
#
# See the file LICENCE for copying permission.

import os
import utils
import sys

def parse_name(data):
    return data.split('\'')[1]

def parse_selector(data):
    if 'selector' in data:
        ret = data.split('selector')[1].split('\'value\':')[1].split(',')[0]
        ret = int(ret.strip()[2:], 16)
        return ret
    return None

def merge(name, selector):
    ret = name
    if selector != None:
        ret = '%s, %d'%(name, selector)
    return ret.__hash__()

def loader(path):
    ret = []
    with open(path, 'rb') as f:
        data = f.read().split('\n')[:-1]
    idx = 0
    while idx < len(data):
        name = parse_name(data[idx])
        selector = parse_selector(data[idx])
        hval = merge(name, selector)
        ret.append(hval)
        idx += 2
    return path, ret

def list_dir(path):
    files = []
    for fn in os.listdir(path):
        files.append(os.path.join(path, fn))
    return files

def get(l, idx):
    if len(l) >idx:
        return l[idx]
    return None

def categorize(groups, idx):
    ret = []
    for group in groups:
        tmp = {}
        for fn, hvals in group:
            hval = get(hvals, idx)
            if hval not in tmp:
                tmp[hval] = []
            tmp[hval].append((fn, hvals))
        for hval in tmp:
            if hval != None :
                ret.append(tmp[hval])
    return ret

def pick_best(groups, n):
    for group in groups:
        if len(group) >= n:
            return group[:n]
    return None

def find_best(groups, n):
    before = None
    idx = 0
    while len(groups) != 0:
        before = groups
        groups = categorize(groups, idx)
        if pick_best(groups, n) == None:
            return pick_best(before, n), idx
        idx += 1
    utils.error('find_best error')

def save_best(path, best_group, idx):
    for fn, _ in best_group:
        name = fn.split('/')[-1]
        with open(fn, 'rb') as f:
            data = f.read().split('\n')[:-1]
        with open(os.path.join(path, name), 'wb') as f:
            for x in data[:idx*2]:
                f.write(x+'\n')

def do_filter(log_path, out_path, n, core):
    log_names = list_dir(log_path)
    logs = utils.multiproc(loader, log_names, core)
    best_group, idx = find_best([logs], n)
    save_best(out_path, best_group, idx)

def show_help():
    print './filter-log [log dir] [output dir] [# of output log] [# of core]'

if __name__ == '__main__':
    if len(sys.argv) !=5:
        show_help()
        sys.exit(-1)

    n = int(sys.argv[3])
    core = int(sys.argv[4])
    do_filter(sys.argv[1], sys.argv[2], n, core)
