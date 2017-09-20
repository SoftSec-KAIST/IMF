# Copyright (c) 2017 HyungSeok Han and Sang Kil Cha at SoftSec, KAIST
#
# See the file LICENCE for copying permission.

import const
import basic
import utils
import sys
VALUE = 0
DATA = 1
ZERO = 'ZERO'

class Model:
    def __init__(self, apisets):
        self.mapis = []
        for idx in range(len(apisets[0])):
            apilog = apisets[0][idx]
            self.mapis.append(Mapi(apilog, idx))
        self.check_const(apisets)
        self.add_dataflow(apisets)

    def check_const(self,apisets):
        for apiset in apisets:
            for idx in range(len(apiset)):
                apilog = apiset[idx]
                self.mapis[idx].check_const(apilog)

    def add_dataflow(self, apisets):
        for apiset in apisets:
            before = {}
            for idx in range(len(apiset)):
                apilog = apiset[idx]
                mapi =self.mapis[idx]
                mapi.add_dataflow(before, apilog)
                update_before(before, apilog, mapi, idx)

    def fuzz(self, header, tail):
        ret = header
        for mapi in self.mapis:
            ret += mapi.to_code(0)
        ret += tail
        return ret

class Mapi(basic.Api):
    def __init__(self, apilog, idx):
        self.api = apilog.api
        self.idx = idx
        self.il, self.ol = {}, {}
        for name,arglog in apilog.get('il').iteritems():
            self.il[name] = Marg(arglog, True)
        for name,arglog in apilog.get('ol').iteritems():
            if not name in self.il:
                self.ol[name] = Marg(arglog, False)

    def check_const(self, apilog):
        ilog = apilog.get('il')
        for name in self.il:
            self.il[name].check_const(ilog[name])

    def add_dataflow(self, before, apilog):
        ilog = apilog.get('il')
        for name in self.il:
            self.il[name].add_dataflow(before, ilog[name])

    def to_code(self, n):
        ret = ''
        arg = ''
        api = self.api
        post = self.get_post()
        if api.get('name') in ['IONotificationPortGetRunLoopSource']:
            return ''

        for _, marg in self.il.iteritems():
            ret += marg.to_code(post, n)
        for _, marg in self.ol.iteritems():
            ret += marg.to_code(post, n)

        for x in api.get('args'):
            arg += '%s_%s, '%(x.get('name'),post)
        arg = arg[:-2]
        name = api.get('name')

        if api.is_void():
            ret += '\t%s(%s);\n'%(name, arg)
        else:
            rname = 'ret_%s'%post
            ret += '\t%s %s = %s(%s);\n'%(api.get('rtype'), rname, name, arg)

        return ret

    def get_post(self):
        return str(self.idx)

    def debug(self):
        for name in self.il:
            print '\t IN  '+name
            self.il[name].debug()
        
        for name in self.ol:
            print '\t OUT '+name
            self.ol[name].debug()

class Marg(basic.Arg):
    def __init__(self,arglog,is_in):
        self.arg = arglog.arg
        self.value = None
        self.data = None
        self.array_flag = False
        self.is_in_flag = is_in
        self.cnt = 0
        name = arglog.get('name')
        if self.arg.is_ptr() and arglog.get_log('value') !=0:
            self.array_flag = True
            self.cnt = arglog.get_log('cnt')
            if is_in:
                self.data = []
                ty = p2d(self.arg.get('type'))
                for _ in range(len(arglog.get_log('data'))):
                    self.data.append(Mval(name, ty, ptr=True))
        if arglog.has_log('ori'):
            self.value = Mval(name, self.arg.get('type'), arglog.get_log('ori'))
        else:
            self.value = Mval(name, self.arg.get('type'))

    def is_array(self):
        return self.array_flag

    def is_in(self):
        return self.is_in_flag

    def to_code(self, post, n):
        ret = ''
        arg = self.arg
        name = '%s_%s'%(arg.get('name'), post)
        ty = arg.get('type').replace('const', '').strip()
        if 'void' in ty and '*' in ty:
            ty = 'uint8_t *'

        if arg.is_ptr():
            if self.cnt ==0:
                ret += '\t%s %s = 0;\n'%(ty, name)
            else:
                nty = ty.replace('*', '').strip()
                ret += '\t%s %s = '%(ty, name)
                ret += 'mut_array('
                ret += 'calloc(%d,sizeof(%s))'%(self.cnt, nty.strip())
                ret += ',%d,sizeof(%s));\n'%(self.cnt, nty)
                if self.is_in():
                    for i in range(self.cnt):
                        v = self.data[i].to_code(n, nty)
                        if v != ZERO:
                            ret += '\t%s[%d] = %s ;\n'%(name, i, v)
        else:
            if arg.is_output() and ty in const.STRING_TYPE:
                return '\t%s %s;\n'%(ty, name)
            v = self.value.to_code(n, ty)
            if v == ZERO:
                v=mut(0, ty)
            ret += '\t%s %s = %s;\n'%(ty, name, v)

        return ret

    def check_const(self, arglog):
        if self.is_array():
            cnt = arglog.get_log('cnt')
            assert(cnt == len(self.data))
            values = arglog.get_log('data')
            for i in range(cnt):
                self.data[i].check_const(values[i])
        value = arglog.get_log('value')
        self.value.check_const(value)

    def add_dataflow(self, before, arglog):
        if self.is_array():
            cnt = arglog.get_log('cnt')
            assert(cnt == len(self.data))
            values = arglog.get_log('data')
            for i in range(cnt):
                self.data[i].add_dataflow(before, values[i])
        value = arglog.get_log('value')
        self.value.add_dataflow(before, value)

    def debug(self):
        if self.is_array():
            print '\tCNT : %d'%self.cnt
            if self.is_in():
                for idx in range(len(self.data)):
                    print '\tDATA : %d'%idx
                    self.data[idx].debug()
        print '\tVALUE'
        self.value.debug()

class Mval:
    def __init__(self,name,ty,ori=None,ptr=False):
        self.value = None
        self.const = None
        self.dataflow = None
        self.raw = []
        self.ori = ori
        self.ty = ty
        self.ptr = ptr
        self.name = name

    def check_const(self,value):
        if self.value == None: 
            self.value = value
        elif self.const or self.const == None:
            if self.value != value:
                self.const = False
            else:
                self.const = True
        return self.const

    def is_const(self):
        return self.const and (not self.ty in const.HANDLES)

    def to_code(self, n, ty):
        ret = ''
        if self.is_const():
            v = self.raw[0]
            if v == 0: 
                return ZERO
            ret += mut(get_value(ty,str(v)),ty)
        else:
            ret += mut(self.get_dataflow(n,ty),ty)
        return ret

    def get_dataflow(self, n, ty):
        dataflow = self.dataflow
        if dataflow != None and len(dataflow) >0:
            mapi, idx = dataflow.keys()[-1]
            pos = dataflow[(mapi,idx)].keys()[0]
            if pos[1] == DATA:
                return '%s_%s[%d]'%(pos[0], mapi.get_post(), pos[2]) 
            elif pos[1] == VALUE:
                return '%s_%s'%(pos[0],mapi.get_post())
            else:
                utils.error('get_dataflow error')
        elif self.ori != None:
            return get_ori(self.ori, ty)
        return get_value(ty, str(self.raw[n]))

    def add_dataflow(self, before, value):
        self.raw.append(value)
        if self.is_const() == False:
            if self.dataflow == None:
                self.dataflow = get_df(before,value)
            else:
                self.dataflow = get_inter_df(before,value,self.dataflow)

    def debug(self):
        print '\t\tCONST : %s'%(str(self.const))
        print '\t\t'+str(self.dataflow)
        print '\t\t'+str(self.raw)

def update_before(before, apilog, mapi, n):
    dic = apilog.get('ol')
    if not apilog.is_void():
        dic[const.RVAL] = apilog.get('rval_log')
    for name, arglog in dic.iteritems():
        value = arglog.get_log('value')
        key = value
        add_before(before, key, mapi, n, (name,VALUE,0))

        if arglog.is_ptr() and value !=0:
            data = arglog.get_log('data')
            for idx in range(len(data)):
                add_before(before, data[idx], mapi, n, (name,DATA,idx))

#key = apilog,n ; pos = arg,DATA,n
def add_before(before, value, mapi, n, pos):
    key = mapi,n
    if not value in before:
        before[value] = {}
    if not key in before[value]:
        before[value][key] = {}
    before[value][key][pos] = True

def get_df(before, value):
    ret = {}
    if value in before:
        df = before[value]
        for key1 in df:
            ret[key1] = {}
            for key2 in df[key1]:
                ret[key1][key2] = df[key1][key2]
    return ret

def get_inter_df(before, value, df):
    ret = {}
    if value in before:
        for key1 in df:
            if key1 in before[value]:
                for key2 in df[key1]:
                    if key2 in before[value][key1]:
                        if not key1 in ret :
                            ret[key1] = {}
                        ret[key1][key2] = True
    return ret

def p2d(ty):
    ret = ''
    cnt = 0
    for x in ty:
        if '*' == x and cnt == 0:
            cnt += 1
        else:
            ret += x
    return ret

def get_ori(ori, ty):
    if type(ori) == type({}) and 'CFDictionaryRef' ==ty:
        if 'IOProviderClass' in ori:
            return 'IOServiceMatching(\"%s\")'%ori['IOProviderClass']
        elif 'IONameMatch' in ori:
            return 'IOServiceNameMatching(\"%s\")'%ori['IONameMatch']
        elif 'BSD Name' in ori:
            tmp = ori['BSD Name']
            if tmp == '(null)':
                return 'IOBSDNameMatching(0,0,0)'
            return 'IOBSDNameMatching(0,0,\"%s\")'%tmp
        elif 'IORegistryEntryID' in ori:
            return 'IORegistryEntryIDMatching(%d)'%ori['IORegistryEntryID']
        return make_cfdic(ori)
    return str(ori)

def get_value(ty, value):
    if ty in ['io_name_t', 'io_string_t']:
        ret = '{'
        for x in value[1:-1]:
            ret+= '%d,'%ord(x)
        ret += '0}'
        return ret
    return value

def make_cfdic(ori):
    if type(ori) == type({}):
        ret = 'make_CFDic()'
        for key in ori:
            v1 = make_cfdic(key)
            v2 = make_cfdic(ori[key])
            ret = 'set_CFDic(%s,%s,%s)'%(ret, v1, v2)
        return ret
    elif type(ori) == type(''):
        return 'CFSTR(\"%s\")'%ori
    elif type(ori) == type(1):
        return 'make_CFNum(%d)'%ori
    elif ori == True:
        return 'kCFBooleanTrue'
    elif ori == False:
        return 'kCFBooleanFalse'
    utils.error('make_cfdic error')

def mut(value, ty):
    nty = ''
    if ty in ['io_string_t', 'io_name_t']:
        ret = '{'
        for x in value[1:-1].split(','):
            ret += 'mut_byte(%s),'%x
        ret = ret[:-1]+'}'
        return ret
    elif '*' in ty or ty in const.TYPE_PTR:
        nty = 'ptr'
    elif ty in const.TYPE_SIZE:
        size = const.TYPE_SIZE[ty]
        if size == 1:
            nty = 'byte'
        elif size == 2:
            nty = 'short'
        elif size == 4:
            nty = 'int'
        elif size == 8:
            nty = 'long'
    if nty == '':
        utils.error('mut error : %s'%ty)

    return '(%s) mut_%s(%s)'%(ty, nty, str(value))
