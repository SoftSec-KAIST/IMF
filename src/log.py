# Copyright (c) 2017 HyungSeok Han and Sang Kil Cha at SoftSec, KAIST
#
# See the file LICENCE for copying permission.

import basic
import const
import utils

class ApiLog(basic.Api):
    def __init__(self, api, il, ol):
        self.__dict__ = api.__dict__.copy()
        self.api = api
        self.args_dict = {}
        self.il = {}
        self.ol = {}
        self.hval = None

        for arg in self.args:
            name = arg.get('name')
            self.args_dict[name] = arg

        for ilog in il[1:]:
            name = ilog['name']
            self.il[name]  = ArgLog(self.args_dict[name], ilog, True)

        for olog in ol[1:]:
            name = olog['name']
            if name == const.RVAL:
                self.rval_log = ArgLog(self.rval, olog, False)
            else:
                self.ol[name]  = ArgLog(self.args_dict[name], olog, False)

class ArgLog(basic.Arg):
    def __init__(self, arg, log, is_input):
        self.__dict__ = arg.__dict__.copy()
        self.arg = arg
        self.log = log
        self.is_input = is_input

    def get_log(self,v):
        if v in self.log :
            return self.log[v]
        utils.error('get_log error')

    def has_log(self,v):
        if v in self.log:
            return True
        return False
