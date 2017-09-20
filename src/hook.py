# Copyright (c) 2017 HyungSeok Han and Sang Kil Cha at SoftSec, KAIST
#
# See the file LICENCE for copying permission.

import basic
import const
import sys
import os

class ApiHook(basic.Api):
    def __init__(self, api):
        self.__dict__ = api.__dict__.copy()
        self.arghooks= []
        for arg in self.args:
            self.arghooks.append(ArgHook(arg))

    def list_args(self, show_type):
        ret = ''
        for x in self.arghooks:
            if show_type :
                ret += '%s %s,'%(x.get('type'), x.get('name'))
            else:
                ret += '%s,'%x.get('name')
        return ret[:-1]

    def log(self):
        body = self.log_intro()
        body += self.log_input()
        body += self.call_ori()
        body += self.log_output()
        args = self.list_args(True)
        return '%s fake_%s(%s){\n%s}\n'%(self.rtype, self.name, args, body)

    def log_intro(self):
        intro = '\tFILE *fp = fopen(log_path,"a");\n'
        intro +='\tflock(fileno(fp),LOCK_EX);\n'
        return intro

    def log_input(self):
        ret = ''
        for arghook in self.arghooks:
            if arghook.is_input():
                ret += arghook.log()
        ret = '''\tfprintf(fp,"IN ['%s',");\n'''%(self.name) +ret
        return ret +'''\tfprintf(fp,"]\\n");\n'''

    def call_ori(self):
        args = self.list_args(False)
        if self.is_void() :
            return  '\t%s(%s);\n'%(self.name, args)
        return '\t%s ret = %s(%s);\n'%(self.rtype,self.name, args)

    def log_output(self):
        ret = ArgHook(self.rval).log()
        for arghook in self.arghooks:
            if arghook.is_output():
                ret += arghook.log()
        ret = '''\tfprintf(fp,"OUT ['%s',");\n'''%(self.name) +ret
        ret += '''\tfprintf(fp,"]\\n");\n'''
        ret += '\tfclose(fp);\n'
        if not self.is_void():
            ret += '\treturn ret;\n'
        return ret

    def hook_entry(self):
        return ('fake_%s'%self.name, self.name)

class ArgHook(basic.Arg):
    def __init__(self,arg):
        self.__dict__ = arg.__dict__.copy()

    def log(self):
        if self.name == const.RVAL and self.type == 'void':
            return ''
        ret, add, add_arg  = '', '', ''

        if (self.is_input() and self.name != const.RVAL) and \
                (self.type in const.CHECK_ORIGINAL):
            ret += '''\tchar name_buf[0x100];\n'''
            ret += '''\tIORegistryEntryGetName(%s,name_buf);\n'''%self.name 
            add += "'ori':'IOServiceGetMatchingService(0,IOServiceMatching(\\\"%s\\\"))',"
            add_arg+= ',name_buf'

        log_name = self.get_log_name()
        fmt = self.get_fmt()

        ret += '\tif(%s) '%(self.valid_ptr())
        ret += '''fprintf(fp,"{'name':'%s','''%self.name
        ret += ''''value': %s,'''%fmt
        ret += ''''size' : 0x%%lx,'cnt':0x%%x,%s '''%add
        ret += ''''data':[",%s, sizeof(%s),'''%(log_name, self.type)
        ret += '''%s%s);\n '''%(self.get_opt('cnt'), add_arg)

        ret += '''\telse fprintf(fp,"{'name':'%s','''%self.name
        ret += ''''value': %s, '''%fmt
        ret += ''''size' : 0x%%lx,'cnt':'undefined',%s '''%add
        ret += ''''data':[",%s,sizeof(%s)%s);\n'''%(log_name, self.type, add_arg)

        if self.is_ptr():
            ret += self.log_ptr()

        if self.is_input() and self.name!=const.RVAL and \
                (self.type in const.CHECK_CF):
            ret += '''\tfprintf(fp,"],'ori':");\n'''
            ret += '''\tlog_CFTypeRef(fp,%s);\n'''%self.name
            ret += '''\tfprintf(fp,"},");\n'''

        else:
            ret += '''\tfprintf(fp,"]},");\n '''
        return ret

    def log_ptr(self):
        template = '''\tif(%s){\n\t\tfor(int i=0; i<%s;i++){\n%s\t\t}\n\t}\n'''
        name = self.name
        if 'void *' in self.type:
            name = '((uint8_t *) %s)'%name
        body = '''\t\t\tfprintf(fp,"%s,",%s[i]);\n'''%(self.get_fmt(True), name)
        return template%(self.valid_ptr(self.name), self.get_opt('cnt'), body)

    def get_log_name(self):
        name = self.name
        if 'CFStringRef' == self.type :
            return 'CFStringGetCStringPtr(%s,kCFStringEncodingMacRoman)'%name
        return name

    def get_fmt(self,for_ptr = False):
        ty = self.type.replace('const','').strip()
        if ty in const.TYPE_FMT:
            return const.TYPE_FMT[ty]
        if not for_ptr and self.is_ptr():
            return '%p'
        return const.SIZE_FMT[self.get_opt('size')]

    def valid_ptr(self,init='1'):
        ret = init
        cnt = str(self.get_opt('cnt'))
        for idx in range(len(cnt)):
            if cnt[idx] != '*' :
                break
            ret = '%s && '%cnt[idx+1:]+ret
        return ret

class Hooker:
    def __init__(self):
        self.apis = basic.load_apis()

    def gen_hook(self, fn_hook):
        code = const.HEADER
        table = const.HOOK_TABLE_TEMPLATE
        entry = const.HOOK_ENTRY_TEMPLATE
        tmp = ''
        for name, api in self.apis.iteritems():
            h = ApiHook(api)
            code += h.log()
            tmp += entry%h.hook_entry()
        code += table%tmp
        with open(fn_hook,'wb') as f:
            f.write(code)

def show_help():
    print ' ./gen-hook [name of hooking code]'

if __name__ == '__main__':
    if len(sys.argv) != 2:
        show_help()
        sys.exit(0)

    hooker = Hooker()
    hooker.gen_hook(sys.argv[1])

