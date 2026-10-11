# SPDX-License-Identifier: GPL-2.0-only
from build_common import *

def build_native(cfg,out,project,nt):
    src=out/'work';copytree(project/'native',src)
    inc=src/'include';dll=src/'ntdll';lib=src/'libntc';nttools=nt/'tools/x86'
    gen=load(dll/'gen_syscalls.py','syscalls')
    services=gen.parse_services(nt/'base/ntos/ke/services.tab')
    if len(services)!=284: raise RuntimeError('Unexpected syscall table')
    gen.generate_asm(services,dll/'syscalls.asm');gen.generate_def(services,dll/'ntdll.def');gen.generate_header(services,inc/'ntsyscall.h')
    objects=[]
    env=os.environ.copy();env['PATH']=str(nttools)+';'+env.get('PATH','')
    for asm in ('syscalls','dispatch'):
        obj=out/(asm+'.obj');run([nttools/'ml.exe','/nologo','/c','/coff','/Fo'+str(obj),dll/(asm+'.asm')],env=env);objects.append(obj)
    for name in ('rtl_minimal','ldr_pe','ldr_elf'):
        obj=out/(name+'.obj');run([nttools/'cl.exe','/nologo','/c','/O1','/Os','/Gy','/W3','/Zl','/I'+str(inc),'/Fo'+str(obj),dll/(name+'.c')],env=env);objects.append(obj)
    int64=nt/'public/sdk/lib/i386/int64.lib'
    run([nttools/'link.exe','/NOLOGO','/DLL','/SUBSYSTEM:NATIVE,5.01','/BASE:0x77F50000','/ENTRY:_DllMainCRTStartup@12','/NODEFAULTLIB','/RELEASE','/DEF:'+str(dll/'ntdll.def'),'/OUT:'+str(out/'ntdll.dll'),'/IMPLIB:'+str(out/'ntdll.lib'),*objects,int64],env=env)
    objects=[]
    for source in sorted(lib.glob('*.c'))+sorted(lib.glob('*.cc')):
        obj=out/(source.stem+'.obj');run([nttools/'cl.exe','/nologo','/c','/O1','/Os','/Gy','/Gs1048576','/W3','/Zl','/X','/I'+str(inc),'/Fo'+str(obj),('/Tp'+str(source)) if source.suffix=='.cc' else source],env=env);objects.append(obj)
    run([nttools/'lib.exe','/NOLOGO','/OUT:'+str(out/'libntc.lib'),*objects,int64],env=env)
    copytree(inc,out/'include');shutil.rmtree(src)

