# Copyright (c) 2017 HyungSeok Han and Sang Kil Cha at SoftSec, KAIST
#
# See the file LICENCE for copying permission.

RVAL = 'ret'
DCNT = 1 #Defualt Cnt
DSIZE = 4 # Defualt Size
TYPE_FMT = {'char *' : """'\\"%s\\"'""", 
            'const char *': """'\\"%s\\"'""", 
            'io_name_t': """'\\"%s\\"'""", 
            'const io_name_t': """'\\"%s\\"'""",
            'CFStringRef': """'CFSTR(\\"%s\\")'""",
            'io_string_t': """'\\"%s\\"'"""
            }
SIZE_FMT = {1: '0x%hhx', 2: '0x%hx', 4: '0x%x', 8: '0x%llx'}
DEBUG = True
MULTI_NUM =4
DATA = 'DATA'
VALUE = 'VALUE'
TYPE_PTR = ['CFDictionaryRef', 'IONotificationPortRef',
            'io_name_t', 'CFStringRef', 'char *']
TYPE_SIZE = {'uint8_t':1, 'IOServiceMatchingCallback':4, 'CFDictionaryRef':4,
             'const void *':4, 'int':4,'io_name_t':128, 'vm_address_t':4,
             'io_iterator_t':4, 'const uint64_t *':4, 'const io_string_t':512,
             'CFStringRef':4, 'mach_timespec_t *':4, 'size_t':4,
             'boolean_t *':4, 'CFTypeRef':4, 'IONotificationPortRef':4,
             'CFMutableDictionaryRef *':4, 'const io_name_t':128,
             'mach_vm_address_t':8, 'io_service_t *':4, 'uint32_t *':4,
             'IOOptionBits':4, 'io_registry_entry_t':4, 'io_connect_t *':4,
             'vm_address_t *':4, 'io_struct_inband_t':4096, 'const char *':4,
             'CFAllocatorRef':4, 'mach_vm_size_t *':4, 'uintptr_t':4,
             'CFRunLoopSourceRef':4, 'io_iterator_t *':4,
             'io_registry_entry_t *':4, 'void':1, 'uint64_t *':4, 'size_t *':4,
             'vm_size_t *':4, 'char **':4, 'kern_return_t':4,
             'CFMutableDictionaryRef':4, 'IOServiceInterestCallback':4,
             'io_object_t *':4, 'mach_port_t':4, 'uintptr_t *':4,
             'io_object_t':4, 'io_service_t':4, 'io_connect_t':4,
             'task_port_t':4, 'void **':4, 'void *':4, 'mach_msg_header_t *':4,
             'uint32_t':4, 'boolean_t':4, 'uint64_t':8, 'mach_vm_address_t *':4,
             'mach_port_t *':4,'io_string_t':512
             }
CHECK_ORIGINAL = ['io_service_t', 'io_registry_entry_t']
CHECK_CF = ['CFDictionaryRef', 'CFTypeRef']
STRING_TYPE = ['io_string_t', 'io_name_t', 'io_struct_inband_t']
HANDLES =  ['io_connect_t', 'mach_port_t', 'io_iterator_t', 'io_object_t',
            'io_registry_entry_t', 'io_service_t']
HOOK_ENTRY_TEMPLATE = '\t{ .replacement = (void*)%40s, .original = (void*)%35s},\n'
HOOK_TABLE_TEMPLATE = '''
typedef struct interposer {
    void* replacement;
      void* original;
} interpose_t;
__attribute__((used)) static const interpose_t interposers[]
  __attribute__((section("__DATA, __interpose"))) = {
    %s
  };
'''
HEADER = '''
/*
Copyright (c) 2017 HyungSeok Han and Sang Kil Cha at SoftSec, KAIST

See the file LICENCE for copying permission.
*/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <IOKit/IOKitLib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/file.h>
#include <CoreFoundation/CoreFoundation.h>

#ifndef LOG_PATH
#define LOG_PATH "/tmp/log"
#endif

const char* log_path = LOG_PATH;
void log_CFTypeRef(FILE *f,CFTypeRef target){
  CFTypeID ty = CFGetTypeID(target);
  if (ty == CFStringGetTypeID()){
    fprintf(f,"'%s'",CFStringGetCStringPtr(target,kCFStringEncodingUTF8));
  }else if (ty == CFDictionaryGetTypeID()){
    fprintf(f,"{");
    size_t size = CFDictionaryGetCount(target);
    CFTypeRef *keys = (CFTypeRef *) malloc( size * sizeof(CFTypeRef) );
    CFTypeRef *vals = (CFTypeRef *) malloc( size * sizeof(CFTypeRef) );
    CFDictionaryGetKeysAndValues(target,keys,vals);
    for(size_t i=0;i<size; i++){
      log_CFTypeRef(f,keys[i]);
      fprintf(f,":");
      log_CFTypeRef(f,vals[0]);
      fprintf(f,",");
    
    }
    fprintf(f,"}");
    free(keys);
    free(vals);
  }else if (ty == CFNumberGetTypeID()){
    uint64_t n;
    CFNumberGetValue(target,CFNumberGetType(target),&n);
    fprintf(f,"%d",n);
  }else if (ty == CFBooleanGetTypeID()){
    fprintf(f,"%s",CFBooleanGetValue(target)?"True":"False");
  }else{
    fprintf(f,"log_CFTypeRef ERROR");
    exit(0);
  }
}
'''
CODE_HEAD = '''
/*
Copyright (c) 2017 HyungSeok Han and Sang Kil Cha at SoftSec, KAIST

See the file LICENCE for copying permission.
*/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <IOKit/IOKitLib.h>
#include <fcntl.h>
#include <unistd.h>
#include <CoreFoundation/CoreFoundation.h>

#define MAYBE (get_rand32() % rate == 0)
unsigned int first = 1;
unsigned int set_seed = 0;
const char* log_file = NULL;
unsigned int seed = 0;
unsigned int bitlen = 8;
unsigned int rate = 1000;
unsigned int max_loop = 1000;
uint16_t get_rand(){
  short ret;
  if(first ==1){
    if(set_seed == 0){
      int fd;
      fd = open("/dev/urandom",0);
      read(fd,&seed,4);
      close(fd);
      FILE *fp = fopen(log_file,"a");
      fprintf(fp,"seed: %ld, rate: %ld, bitlen: %ld, max_loop: %ld\\n", seed, rate,
              bitlen, max_loop);
      fclose(fp);
      sync();
    }
    srand(seed);
    first = 0;
  }
  ret = (uint16_t)rand() & 0xffff;
  return ret;
}
uint32_t get_rand32(){
  uint32_t ret = (get_rand() << 16) | get_rand();
  return ret;
}
CFMutableDictionaryRef make_CFDic(){
  return CFDictionaryCreateMutable(NULL,0,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
}

CFMutableDictionaryRef set_CFDic(CFMutableDictionaryRef dic, CFTypeRef key, CFTypeRef val){
  CFDictionarySetValue(dic,key,val);
  return dic;
}
CFNumberRef make_CFNum(int value){
  int *ptr = malloc(sizeof(int));
  *ptr = value;
  return CFNumberCreate(NULL,kCFNumberIntType,ptr);
}

boolean_t mut_bool(boolean_t v){
  if( MAYBE ){
    if((get_rand() & 1) ==0) return false;
    return true;
  }
  return v;
}
uint8_t mut_byte(uint8_t v){
  uint8_t r ;
  if( MAYBE ){
    r= (uint16_t)get_rand() ;
    if(bitlen <8){
      return v ^ (r & ((1 << (8-bitlen))-1) ); 
    }else{
      return v ^ (r & 1) ;
    }
  }
  return v;
}

uint16_t mut_short(uint16_t v){
  uint16_t r ;
  if( MAYBE ){
    r= get_rand();
    if(bitlen <16){
      return v ^ (r & ((1 << (16-bitlen))-1) ); 
    }else{
      return v ^ (r & 1) ;
    }
  }
  return v;
}

uint32_t mut_int(uint32_t v){
  uint32_t r =0;
  if( MAYBE ){
    r = (r<<16) | (uint32_t) get_rand();
    r = (r<<16) | (uint32_t) get_rand();
    if(bitlen <32){
      return v ^ (r & ((1 << (32-bitlen))-1) ); 
    }else{
      return v ^ (r & 1) ;
    }

  }
  return v;
}

uint64_t mut_long(uint64_t v){
  uint64_t r = 0;
  if( MAYBE ){
    r = (r<<16) | (uint64_t) get_rand();
    r = (r<<16) | (uint64_t) get_rand();
    r = (r<<16) | (uint64_t) get_rand();
    r = (r<<16) | (uint64_t) get_rand();

    if(bitlen <64){
      return v ^ (r & (((uint64_t)1 << (64-bitlen))-1) ); 
    }else{
      return v ^ (r & 1) ;
    }
  }
  return v;
}

void* mut_ptr(void *v){
  if ( MAYBE ){
    if(sizeof(void *) ==4 ) return (void *)mut_int((uint32_t)v);
    else return (void *)mut_long((uint64_t)v);
  }
  return v;
}

void* mut_array(void *v, uint32_t len, uint32_t size){
  uint32_t i = 0;
  if(size == 1){
    for(i=0; i<len; i++){
      ((uint8_t *)v)[i] = mut_byte(((uint8_t *)v)[i]);
    }
  }else if(size == 2){
    for(i=0; i<len; i++){
      ((uint16_t *)v)[i] = mut_short(((uint16_t *)v)[i]);
    }
  }else if(size == 4){
    for(i=0; i<len; i++){
      ((uint32_t *)v)[i] = mut_int(((uint32_t *)v)[i]);
    }
  }else if(size == 8){
    for(i=0; i<len; i++){
      ((uint64_t *)v)[i] = mut_long(((uint64_t *)v)[i]);
    }
  }
  return v;
}
void help(){
    puts("./fuzz -f [log path] -s [seed] -b [bitlen] -r [rate] -l [# of max loops]");
    puts("\\t-f [log path] : required");
    puts("\\t-b [bitlen] : default = 8");
    puts("\\t-r [rate] : default = 1000");
    puts("\\t-l [# of max loops] : default = 1000");
    puts("\\t-s [seed] : default = random value");
    exit(0);
}

unsigned int parse_uint(char *data){
    char *ptr;
    unsigned int ret = strtoul(data, &ptr, 10);
    if(ret == 0){
        help();
    }
    return ret;
}

void parse_args(int argc, char **argv){
    int opt;
    while ((opt = getopt(argc, argv, "f:s:b:r:l:")) != -1){
        switch(opt){
            case 'f':
                log_file = optarg;
                break;
            case 's':
                seed = parse_uint(optarg);
                set_seed = 1;
                break;
            case 'b':
                bitlen = parse_uint(optarg);
                break;
            case 'r':
                rate = parse_uint(optarg);
                break;
            case 'l':
                max_loop = parse_uint(optarg);
                break;
            default :
                help();
        }

    }
    if(log_file == NULL && set_seed == 0){
        help();
    }
}
int main(int argc, char **argv){
  parse_args(argc, argv);
  unsigned int loop=0;
  while(loop<max_loop){

'''
CODE_TAIL = '''
    loop++;
  }
}
'''
API_DEFS = [
[('kern_return_t', 'IOMasterPort'), [('mach_port_t', 'bootstrapPort', {}), ('mach_port_t *', 'masterPort', {'IO': 'O'})]],
[('IONotificationPortRef', 'IONotificationPortCreate'), [('mach_port_t', 'masterPort', {})]],
[('void', 'IONotificationPortDestroy'), [('IONotificationPortRef', 'notify', {})]],
[('CFRunLoopSourceRef', 'IONotificationPortGetRunLoopSource'), [('IONotificationPortRef', 'notify', {})]],
[('mach_port_t', 'IONotificationPortGetMachPort'), [('IONotificationPortRef', 'notify', {})]],
[('void', 'IODispatchCalloutFromMessage'), [('void *', 'unused', {}), ('mach_msg_header_t *', 'msg', {}), ('void *', 'reference', {})]],
[('kern_return_t', 'IOCreateReceivePort'), [('uint32_t', 'msgType', {}), ('mach_port_t *', 'recvPort', {'IO': 'O'})]],
[('kern_return_t', 'IOObjectRelease'), [('io_object_t', 'object', {})]],
[('kern_return_t', 'IOObjectRetain'), [('io_object_t', 'object', {})]],
[('kern_return_t', 'IOObjectGetClass'), [('io_object_t', 'object', {}), ('io_name_t', 'className', {'IO':'O'})]],
[('CFStringRef', 'IOObjectCopyClass'), [('io_object_t', 'object', {})]],
[('CFStringRef', 'IOObjectCopySuperclassForClass'), [('CFStringRef', 'classname', {})]],
[('CFStringRef', 'IOObjectCopyBundleIdentifierForClass'), [('CFStringRef', 'classname', {})]],
[('boolean_t', 'IOObjectConformsTo'), [('io_object_t', 'object', {}), ('const io_name_t', 'className', {})]],
[('boolean_t', 'IOObjectIsEqualTo'), [('io_object_t', 'object', {}), ('io_object_t', 'anObject', {})]],
[('uint32_t', 'IOObjectGetKernelRetainCount'), [('io_object_t', 'object', {})]],
[('uint32_t', 'IOObjectGetUserRetainCount'), [('io_object_t', 'object', {})]],
[('uint32_t', 'IOObjectGetRetainCount'), [('io_object_t', 'object', {})]],
[('io_object_t', 'IOIteratorNext'), [('io_iterator_t', 'iterator', {})]],
[('void', 'IOIteratorReset'), [('io_iterator_t', 'iterator', {})]],
[('boolean_t', 'IOIteratorIsValid'), [('io_iterator_t', 'iterator', {})]],
[('io_service_t', 'IOServiceGetMatchingService'), [('mach_port_t', 'masterPort', {}), ('CFDictionaryRef', 'matching', {})]],
[('kern_return_t', 'IOServiceGetMatchingServices'), [('mach_port_t', 'masterPort', {}), ('CFDictionaryRef', 'matching', {}), ('io_iterator_t *', 'existing', {'IO':'O'})]],
[('kern_return_t', 'IOServiceAddMatchingNotification'), [('IONotificationPortRef', 'notifyPort', {}), ('const io_name_t', 'notificationType', {}), ('CFDictionaryRef', 'matching', {}), ('IOServiceMatchingCallback', 'callback', {}), ('void *', 'refCon', {'IO':'O'}), ('io_iterator_t *', 'notification', {'IO':'O'})]],
[('kern_return_t', 'IOServiceAddInterestNotification'), [('IONotificationPortRef', 'notifyPort', {}), ('io_service_t', 'service', {}), ('const io_name_t', 'interestType', {}), ('IOServiceInterestCallback', 'callback', {}), ('void *', 'refCon', {}), ('io_object_t *', 'notification', {'IO':'O'})]],
[('kern_return_t', 'IOServiceMatchPropertyTable'), [('io_service_t', 'service', {}), ('CFDictionaryRef', 'matching', {}), ('boolean_t *', 'matches', {})]],
[('kern_return_t', 'IOServiceGetBusyState'), [('io_service_t', 'service', {}), ('uint32_t *', 'busyState', {})]],
[('kern_return_t', 'IOServiceWaitQuiet'), [('io_service_t', 'service', {}), ('mach_timespec_t *', 'waitTime', {})]],
[('kern_return_t', 'IOKitGetBusyState'), [('mach_port_t', 'masterPort', {}), ('uint32_t *', 'busyState', {})]],
[('kern_return_t', 'IOKitWaitQuiet'), [('mach_port_t', 'masterPort', {}), ('mach_timespec_t *', 'waitTime', {})]],
[('kern_return_t', 'IOServiceOpen'), [('io_service_t', 'service', {}), ('task_port_t', 'owningTask', {}), ('uint32_t', 'type', {}), ('io_connect_t *', 'connect', {'IO': 'O'})]],
[('kern_return_t', 'IOServiceRequestProbe'), [('io_service_t', 'service', {}), ('uint32_t', 'options', {})]],
[('kern_return_t', 'IOServiceAuthorize'), [('io_service_t', 'service', {}), ('uint32_t', 'options', {})]],
[('int', 'IOServiceOpenAsFileDescriptor'), [('io_service_t', 'service', {}), ('int', 'oflag', {})]],
[('kern_return_t', 'IOServiceClose'), [('io_connect_t', 'connect', {})]],
[('kern_return_t', 'IOConnectAddRef'), [('io_connect_t', 'connect', {})]],
[('kern_return_t', 'IOConnectRelease'), [('io_connect_t', 'connect', {})]],
[('kern_return_t', 'IOConnectGetService'), [('io_connect_t', 'connect', {}), ('io_service_t *', 'service', {'IO':'O'})]],
[('kern_return_t', 'IOConnectSetNotificationPort'), [('io_connect_t', 'connect', {}), ('uint32_t', 'type', {}), ('mach_port_t', 'port', {}), ('uintptr_t', 'reference', {})]],
[('kern_return_t', 'IOConnectMapMemory'), [('io_connect_t', 'connect', {}), ('uint32_t', 'memoryType', {}), ('task_port_t', 'intoTask', {}), ('vm_address_t *', 'atAddress', {'IO': 'O'}), ('vm_size_t *', 'ofSize', {'IO': 'O'}), ('IOOptionBits', 'options', {})]],
[('kern_return_t', 'IOConnectMapMemory64'), [('io_connect_t', 'connect', {}), ('uint32_t', 'memoryType', {}), ('task_port_t', 'intoTask', {}), ('mach_vm_address_t *', 'atAddress', {'IO': 'O', 'size': 8}), ('mach_vm_size_t *', 'ofSize', {'IO': 'O', 'size': 8}), ('IOOptionBits', 'options', {})]],
[('kern_return_t', 'IOConnectUnmapMemory'), [('io_connect_t', 'connect', {}), ('uint32_t', 'memoryType', {}), ('task_port_t', 'fromTask', {}), ('vm_address_t', 'atAddress', {})]],
[('kern_return_t', 'IOConnectUnmapMemory64'), [('io_connect_t', 'connect', {}), ('uint32_t', 'memoryType', {}), ('task_port_t', 'fromTask', {}), ('mach_vm_address_t', 'atAddress', {})]],
[('kern_return_t', 'IOConnectSetCFProperties'), [('io_connect_t', 'connect', {}), ('CFTypeRef', 'properties', {})]],
[('kern_return_t', 'IOConnectSetCFProperty'), [('io_connect_t', 'connect', {}), ('CFStringRef', 'propertyName', {}), ('CFTypeRef', 'property', {})]],
[('kern_return_t', 'IOConnectCallMethod'), [('mach_port_t', 'connection', {}), ('uint32_t', 'selector', {}), ('const uint64_t *', 'input', {'cnt': 'inputCnt', 'IO': 'I', 'size': 8}), ('uint32_t', 'inputCnt', {}), ('const void *', 'inputStruct', {'cnt': 'inputStructCnt', 'IO': 'I', 'size': 1}), ('size_t', 'inputStructCnt', {}), ('uint64_t *', 'output', {'cnt': '*outputCnt', 'IO': 'O', 'size': 8}), ('uint32_t *', 'outputCnt', {'cnt': 1, 'IO': 'IO', 'size': 4,}), ('void *', 'outputStruct', {'cnt': '*outputStructCnt', 'IO': 'O', 'size': 1}), ('size_t *', 'outputStructCnt', {'cnt': 1, 'IO': 'IO', 'size': 4,})]],
[('kern_return_t', 'IOConnectCallAsyncMethod'), [('mach_port_t', 'connection', {}), ('uint32_t', 'selector', {}), ('mach_port_t', 'wake_port', {}), ('uint64_t *', 'reference', {'cnt': 'referenceCnt', 'IO': 'I', 'size': 8}), ('uint32_t', 'referenceCnt', {}), ('const uint64_t *', 'input', {'cnt': 'inputCnt', 'IO': 'I', 'size': 8}), ('uint32_t', 'inputCnt', {}), ('const void *', 'inputStruct', {'cnt': 'inputStructCnt', 'IO': 'I', 'size': 1}), ('size_t', 'inputStructCnt', {}), ('uint64_t *', 'output', {'cnt': '*outputCnt', 'IO': 'O', 'size': 8}), ('uint32_t *', 'outputCnt', {'cnt': 1, 'IO': 'IO', 'size': 4,}), ('void *', 'outputStruct', {'cnt': '*outputStructCnt', 'IO': 'O', 'size': 1}), ('size_t *', 'outputStructCnt', {'cnt': 1, 'IO': 'IO', 'size': 4,})]],
[('kern_return_t', 'IOConnectCallStructMethod'), [('mach_port_t', 'connection', {}), ('uint32_t', 'selector', {}), ('const void *', 'inputStruct', {'cnt': 'inputStructCnt', 'IO': 'I', 'size': 1}), ('size_t', 'inputStructCnt', {}), ('void *', 'outputStruct', {'cnt': '*outputStructCnt', 'IO': 'O', 'size': 1}), ('size_t *', 'outputStructCnt', {'cnt': 1, 'IO': 'IO', 'size': 4,})]],
[('kern_return_t', 'IOConnectCallAsyncStructMethod'), [('mach_port_t', 'connection', {}), ('uint32_t', 'selector', {}), ('mach_port_t', 'wake_port', {}), ('uint64_t *', 'reference', {'cnt': 'referenceCnt', 'IO': 'I', 'size': 8}), ('uint32_t', 'referenceCnt', {}), ('const void *', 'inputStruct', {'cnt': 'inputStructCnt', 'IO': 'I', 'size': 1}), ('size_t', 'inputStructCnt', {}), ('void *', 'outputStruct', {'cnt': '*outputStructCnt', 'IO': 'O', 'size': 1}), ('size_t *', 'outputStructCnt', {'cnt': 1, 'IO': 'IO', 'size': 4,})]],
[('kern_return_t', 'IOConnectCallScalarMethod'), [('mach_port_t', 'connection', {}), ('uint32_t', 'selector', {}), ('const uint64_t *', 'input', {'cnt': 'inputCnt', 'IO': 'I', 'size': 8}), ('uint32_t', 'inputCnt', {}), ('uint64_t *', 'output', {'cnt': '*outputCnt', 'IO': 'O', 'size': 8}), ('uint32_t *', 'outputCnt', {'cnt': 1, 'IO': 'IO', 'size': 4,})]],
[('kern_return_t', 'IOConnectCallAsyncScalarMethod'), [('mach_port_t', 'connection', {}), ('uint32_t', 'selector', {}), ('mach_port_t', 'wake_port', {}), ('uint64_t *', 'reference', {'cnt': 'referenceCnt', 'IO': 'I', 'size': 8}), ('uint32_t', 'referenceCnt', {}), ('const uint64_t *', 'input', {'cnt': 'inputCnt', 'IO': 'I', 'size': 8}), ('uint32_t', 'inputCnt', {}), ('uint64_t *', 'output', {'cnt': '*outputCnt', 'IO': 'O', 'size': 8}), ('uint32_t *', 'outputCnt', {'cnt': 1, 'IO': 'IO', 'size': 4,})]],
[('kern_return_t', 'IOConnectTrap0'), [('io_connect_t', 'connect', {}), ('uint32_t', 'index', {})]],
[('kern_return_t', 'IOConnectTrap1'), [('io_connect_t', 'connect', {}), ('uint32_t', 'index', {}), ('uintptr_t', 'p1', {})]],
[('kern_return_t', 'IOConnectTrap2'), [('io_connect_t', 'connect', {}), ('uint32_t', 'index', {}), ('uintptr_t', 'p1', {}), ('uintptr_t', 'p2', {})]],
[('kern_return_t', 'IOConnectTrap3'), [('io_connect_t', 'connect', {}), ('uint32_t', 'index', {}), ('uintptr_t', 'p1', {}), ('uintptr_t', 'p2', {}), ('uintptr_t', 'p3', {})]],
[('kern_return_t', 'IOConnectTrap4'), [('io_connect_t', 'connect', {}), ('uint32_t', 'index', {}), ('uintptr_t', 'p1', {}), ('uintptr_t', 'p2', {}), ('uintptr_t', 'p3', {}), ('uintptr_t', 'p4', {})]],
[('kern_return_t', 'IOConnectTrap5'), [('io_connect_t', 'connect', {}), ('uint32_t', 'index', {}), ('uintptr_t', 'p1', {}), ('uintptr_t', 'p2', {}), ('uintptr_t', 'p3', {}), ('uintptr_t', 'p4', {}), ('uintptr_t', 'p5', {})]],
[('kern_return_t', 'IOConnectTrap6'), [('io_connect_t', 'connect', {}), ('uint32_t', 'index', {}), ('uintptr_t', 'p1', {}), ('uintptr_t', 'p2', {}), ('uintptr_t', 'p3', {}), ('uintptr_t', 'p4', {}), ('uintptr_t', 'p5', {}), ('uintptr_t', 'p6', {})]],
[('kern_return_t', 'IOConnectAddClient'), [('io_connect_t', 'connect', {}), ('io_connect_t', 'client', {})]],
[('io_registry_entry_t', 'IORegistryGetRootEntry'), [('mach_port_t', 'masterPort', {})]],
[('io_registry_entry_t', 'IORegistryEntryFromPath'), [('mach_port_t', 'masterPort', {}), ('const io_string_t', 'path', {})]],
[('io_registry_entry_t', 'IORegistryEntryCopyFromPath'), [('mach_port_t', 'masterPort', {}), ('CFStringRef', 'path', {})]],
[('kern_return_t', 'IORegistryCreateIterator'), [('mach_port_t', 'masterPort', {}), ('const io_name_t', 'plane', {}), ('IOOptionBits', 'options', {}), ('io_iterator_t *', 'iterator', {'IO':'O'})]],
[('kern_return_t', 'IORegistryEntryCreateIterator'), [('io_registry_entry_t', 'entry', {}), ('const io_name_t', 'plane', {}), ('IOOptionBits', 'options', {}), ('io_iterator_t *', 'iterator', {'IO':'O'})]],
[('kern_return_t', 'IORegistryIteratorEnterEntry'), [('io_iterator_t', 'iterator', {})]],
[('kern_return_t', 'IORegistryIteratorExitEntry'), [('io_iterator_t', 'iterator', {})]],
[('kern_return_t', 'IORegistryEntryGetName'), [('io_registry_entry_t', 'entry', {}), ('io_name_t', 'name', {'IO':'O'})]],
[('kern_return_t', 'IORegistryEntryGetNameInPlane'), [('io_registry_entry_t', 'entry', {}), ('const io_name_t', 'plane', {}), ('io_name_t', 'name', {})]],
[('kern_return_t', 'IORegistryEntryGetLocationInPlane'), [('io_registry_entry_t', 'entry', {}), ('const io_name_t', 'plane', {}), ('io_name_t', 'location', {})]],
[('kern_return_t', 'IORegistryEntryGetPath'), [('io_registry_entry_t', 'entry', {}), ('const io_name_t', 'plane', {}), ('io_string_t', 'path', {"IO":"O"})]],
[('CFStringRef', 'IORegistryEntryCopyPath'), [('io_registry_entry_t', 'entry', {}), ('const io_name_t', 'plane', {})]],
[('kern_return_t', 'IORegistryEntryGetRegistryEntryID'), [('io_registry_entry_t', 'entry', {}), ('uint64_t *', 'entryID', {'IO':'O'})]],
[('kern_return_t', 'IORegistryEntryCreateCFProperties'), [('io_registry_entry_t', 'entry', {}), ('CFMutableDictionaryRef *', 'properties', {'IO':'O'}), ('CFAllocatorRef', 'allocator', {}), ('IOOptionBits', 'options', {})]],
[('CFTypeRef', 'IORegistryEntryCreateCFProperty'), [('io_registry_entry_t', 'entry', {}), ('CFStringRef', 'key', {}), ('CFAllocatorRef', 'allocator', {}), ('IOOptionBits', 'options', {})]],
[('CFTypeRef', 'IORegistryEntrySearchCFProperty'), [('io_registry_entry_t', 'entry', {}), ('const io_name_t', 'plane', {}), ('CFStringRef', 'key', {}), ('CFAllocatorRef', 'allocator', {}), ('IOOptionBits', 'options', {})]],
[('kern_return_t', 'IORegistryEntryGetProperty'), [('io_registry_entry_t', 'entry', {}), ('const io_name_t', 'propertyName', {}), ('io_struct_inband_t', 'buffer', {"IO":"O"}), ('uint32_t *', 'size', {})]],
[('kern_return_t', 'IORegistryEntrySetCFProperties'), [('io_registry_entry_t', 'entry', {}), ('CFTypeRef', 'properties', {})]],
[('kern_return_t', 'IORegistryEntrySetCFProperty'), [('io_registry_entry_t', 'entry', {}), ('CFStringRef', 'propertyName', {}), ('CFTypeRef', 'property', {})]],
[('kern_return_t', 'IORegistryEntryGetChildIterator'), [('io_registry_entry_t', 'entry', {}), ('const io_name_t', 'plane', {}), ('io_iterator_t *', 'iterator', {'IO':'O'})]],
[('kern_return_t', 'IORegistryEntryGetChildEntry'), [('io_registry_entry_t', 'entry', {}), ('const io_name_t', 'plane', {}), ('io_registry_entry_t *', 'child', {'IO':'O'})]],
[('kern_return_t', 'IORegistryEntryGetParentIterator'), [('io_registry_entry_t', 'entry', {}), ('const io_name_t', 'plane', {}), ('io_iterator_t *', 'iterator', {'IO':'O'})]],
[('kern_return_t', 'IORegistryEntryGetParentEntry'), [('io_registry_entry_t', 'entry', {}), ('const io_name_t', 'plane', {}), ('io_registry_entry_t *', 'parent', {'IO':'O'})]],
[('boolean_t', 'IORegistryEntryInPlane'), [('io_registry_entry_t', 'entry', {}), ('const io_name_t', 'plane', {})]],
[('CFMutableDictionaryRef', 'IOServiceMatching'), [('const char *', 'name', {})]],
[('CFMutableDictionaryRef', 'IOServiceNameMatching'), [('const char *', 'name', {})]],
[('CFMutableDictionaryRef', 'IOBSDNameMatching'), [('mach_port_t', 'masterPort', {}), ('uint32_t', 'options', {}), ('const char *', 'bsdName', {})]],
[('CFMutableDictionaryRef', 'IORegistryEntryIDMatching'), [('uint64_t', 'entryID', {})]],
[('kern_return_t', 'OSGetNotificationFromMessage'), [('mach_msg_header_t *', 'msg', {}), ('uint32_t', 'index', {}), ('uint32_t *', 'type', {}), ('uintptr_t *', 'reference', {}), ('void **', 'content', {}), ('vm_size_t *', 'size', {})]],
[('kern_return_t', 'IOCatalogueSendData'), [('mach_port_t', 'masterPort', {}), ('uint32_t', 'flag', {}), ('const char *', 'buffer', {}), ('uint32_t', 'size', {})]],
[('kern_return_t', 'IOCatalogueTerminate'), [('mach_port_t', 'masterPort', {}), ('uint32_t', 'flag', {}), ('io_name_t', 'description', {})]],
[('kern_return_t', 'IOCatalogueGetData'), [('mach_port_t', 'masterPort', {}), ('uint32_t', 'flag', {}), ('char **', 'buffer', {}), ('uint32_t *', 'size', {})]],
[('kern_return_t', 'IOCatalogueModuleLoaded'), [('mach_port_t', 'masterPort', {}), ('io_name_t', 'name', {})]],
[('kern_return_t', 'IOCatalogueReset'), [('mach_port_t', 'masterPort', {}), ('uint32_t', 'flag', {})]],
]
