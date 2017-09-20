# Copyright (c) 2017 HyungSeok Han and Sang Kil Cha at SoftSec, KAIST
#
# See the file LICENCE for copying permission.

import const
import utils

class Api(object):
    def __init__(self, data):
        self.rtype,self.name = data[0]
        self.args = []
        self.rval = Arg((self.rtype,const.RVAL, {}))
        for arg in data[1] :
            self.args.append(Arg(arg))

    def get(self, v):
        if v in self.__dict__:
            return self.__dict__[v]
        utils.error('Api get error: %s'%str(v))

    def is_void(self):
        return 'void' == self.rtype

class Arg(object):
    def __init__(self, arg):
        self.type, self.name,self.opt = arg

    def get(self,v):
        if v in self.__dict__:
            return self.__dict__[v]
        utils.error('Arg get error: %s doesn\'t have %s'%(self.name,str(v)))

    def get_opt(self,v):
        if v in self.opt :
            return self.opt[v]
        elif 'cnt' == v :
            return const.DCNT
        elif 'size' == v :
            return const.DSIZE
        else :
            utils.error('get_opt error')

    def is_input(self):
        if 'IO' in self.opt:
            return 'I' in self.opt['IO']
        return True

    def is_output(self):
        if 'IO' in self.opt:
            return 'O' in self.opt['IO']
        return False

    def is_ptr(self):
        return '*' in self.type  and not 'char' in self.type

def load_apis():
    apis = {}
    for x in const.API_DEFS:
        api = Api(x)
        apis[api.get('name')] = api
    return apis
