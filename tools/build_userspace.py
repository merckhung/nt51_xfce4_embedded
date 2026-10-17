# SPDX-License-Identifier: GPL-2.0-only
from build_common import *

def build_userspace(cfg,out,project,nt):
    variant=cfg['operation'];src=project/variant
    musl=out/'work/musl';bb=out/'work/busybox';copytree(Path(cfg['musl']),musl);copytree(Path(cfg['busybox']),bb)
    shutil.copy2(src/'musl/gen_headers.py',musl/'gen_headers.py');run([sys.executable,musl/'gen_headers.py'])
    (musl/'src/internal/version.h').write_text('#define VERSION "1.2.5"\n')
    shutil.copy2(src/'busybox/.config',bb/'.config')
    for f in (src/'busybox-config').glob('*.h'):shutil.copy2(f,bb/'include'/f.name)
    # Equivalent to the Kbuild generation in upstream scripts/gen_build_files.sh.
    for template in bb.rglob('Kbuild.src'):
        additions=[]
        for source in sorted(template.parent.glob('*.c')):
            additions.extend(line[len('//kbuild:'):] for line in source.read_text(errors='replace').splitlines() if line.startswith('//kbuild:'))
        (template.parent/'Kbuild').write_text(template.read_text().replace('\nINSERT\n','\n'+'\n'.join(additions)+'\n'),newline='\n')
    cc=tool('clang');common=['-target','i386-unknown-linux-musl','-m32','-march=i586','-mno-sse','-mstack-alignment=4','-mstackrealign','-fno-stack-protector','-fno-pie','-fno-pic','-ffreestanding','-nostdinc','-Wno-ignored-attributes']
    libcflags=common+['-std=c99','-D_XOPEN_SOURCE=700','-O2','-I'+str(musl/'arch/i386'),'-I'+str(musl/'arch/generic'),'-I'+str(musl/'src/include'),'-I'+str(musl/'src/internal'),'-I'+str(musl/'include'),'-I'+str(src/'shim')]
    # Match the port's C implementation; only i386 assembly explicitly supported below is linked.
    arches={'aarch64','arm','mips','mips64','mipsn32','powerpc','powerpc64','riscv32','riscv64','s390x','sh','microblaze','m68k','loongarch64','or1k','x32','x86_64'}
    sources=sorted(f for f in (musl/'src').rglob('*.c') if not set(f.relative_to(musl/'src').parts)&arches and not 'ldso' in f.parts)
    # Architecture C files override generic implementations, as in musl's Makefile.
    overrides={f.parent.parent/f.name for f in sources if f.parent.name=='i386'}
    sources=[f for f in sources if f not in overrides]
    objects=compile_many(sources,cc,libcflags,out/'musl-obj')
    # __set_thread_area must use the port's C implementation, not the Linux int80 assembly.
    assembly=[musl/'src/setjmp/i386/setjmp.s',musl/'src/setjmp/i386/longjmp.s']
    objects+=compile_many(assembly,cc,common,out/'musl-asm')
    archive(objects,out/'libc.a')
    flags=common+['-fshort-wchar','-isystem',str(musl/'include'),'-I'+str(src/'shim'),'-I'+str(src/'net'),'-I'+str(src/'usb'),'-O2','-fno-builtin','-D_GNU_SOURCE','-Wno-incompatible-pointer-types','-Wno-int-conversion','-Wno-pointer-sign']
    shims=[src/'shim/nt_linux_shim.c',src/'shim/nt_syscall.s',src/'shim/int64_builtins.c',src/'shim/modtools.c',src/'net/net_stack.c',src/'usb/usb_stack.c',project/'native/unsupported_tools.c',project/'native/ntps.c',project/'native/ntinfo.c']
    if variant in ('rootfs','chromium_rootfs'):shims.append(src/'xfce_probe.c')
    if variant == 'chromium_rootfs':
        gcompat_obj=out/'gcompat.o'
        run([cc,'-target','i386-unknown-linux-musl','-m32','-march=i586','-fPIC','-O2','-I'+str(musl/'include'),'-c',src/'shim/gcompat.c','-o',gcompat_obj])
        libc_stub=out/'libc_stub.so'
        run([tool('ld.lld'),'-m','elf_i386','-shared','-soname','libc.so.6','-o',libc_stub,gcompat_obj])
        run([tool('ld.lld'),'-m','elf_i386','-shared','-soname','ld-linux.so.2','--no-as-needed','--allow-shlib-undefined','--unresolved-symbols=ignore-all','-o',out/'libgcompat.so',gcompat_obj,libc_stub])
        probe_obj=out/'swiftshader_probe.o'
        run([cc,'-target','i386-unknown-linux-musl','-m32','-march=i586','-fPIE','-O2','-I'+str(musl/'include'),'-c',src/'shim/swiftshader_probe.c','-o',probe_obj])
        run([tool('ld.lld'),'-m','elf_i386','-pie','-dynamic-linker','/lib/ld-musl-i386.so.1','--no-as-needed','--allow-shlib-undefined','--unresolved-symbols=ignore-all','-o',out/'swiftshader_probe',probe_obj,libc_stub,out/'libgcompat.so'])
        libc_stub.unlink()
    tests=sorted((project/'tests').glob('*.c'))
    shimobjs=compile_many(shims+tests,cc,flags+['-DLIBNTSHIM_BUILD'],out/'shim-obj');archive(shimobjs,out/'libntshim.a')
    entry=compile_many([src/'shim/entry.c'],cc,flags,out/'entry-obj')[0]
    discover=load(project/'tools/busybox_sources.py','bb_sources');discover.BB_DIR=str(bb)
    bbsources=[Path(s) for _,s in discover.discover_sources()]
    bbflags=flags+['-I'+str(bb/'include'),'-I'+str(bb/'libbb'),'-include',str(bb/'include/autoconf.h'),'-DNDEBUG','-D_LARGEFILE_SOURCE','-D_LARGEFILE64_SOURCE','-D_FILE_OFFSET_BITS=64','-DBB_GLOBAL_CONST=','-Os','-Wno-format-security','-Wno-unused-value','-Wno-parentheses','-Wno-string-plus-int']
    bbobjects=compile_many(bbsources,cc,bbflags,out/'busybox-obj');archive(bbobjects,out/'libbusybox.a')
    applet=bbobjects[bbsources.index(bb/'applets/applets.c')]
    run([tool('ld.lld'),'-m','elf_i386','-static','--image-base=0x01000000','-o',out/'busybox.elf',entry,applet,'--start-group',out/'libbusybox.a',out/'libntshim.a',out/'libc.a','--end-group'])
    run([tool('llvm-strip'),'--strip-all','-o',out/'busybox',out/'busybox.elf'])
    # A standalone suite is packaged as well as the integrated nttest applet.
    testobjects=compile_many(tests,cc,flags,out/'tests-obj')
    run([tool('ld.lld'),'-m','elf_i386','-static','--image-base=0x01000000','-o',out/'nttest.elf',entry,*testobjects,'--start-group',out/'libntshim.a',out/'libc.a','--end-group'])
    native=next(Path(d) for d in cfg['deps'] if Path(d).name=='native.files')
    inc=native/'include';nttools=nt/'tools/x86';env=os.environ.copy();env['PATH']=str(nttools)+';'+env['PATH']
    obj=out/'smss.obj'
    run([nttools/'cl.exe','/nologo','/c','/Zl','/Zp8','/Gy','/Gm-','/GX-','/GR-','/GF','/Gs1048576','/O1','/W3','/I'+str(inc),'/Fo'+str(obj),src/'init/smss.c'],env=env)
    run([nttools/'link.exe','/nologo','/SUBSYSTEM:NATIVE,5.01','/NODEFAULTLIB','/ENTRY:NtProcessStartup','/BASE:0x00800000','/STACK:0x100000,0x40000','/RELEASE','/OUT:'+str(out/'smss.exe'),obj,native/'libntc.lib',native/'ntdll.lib'],env=env)
    drivers=out/'drivers';drivers.mkdir()
    for source in sorted((src/'drivers').glob('*/*.c')):
        obj=drivers/(source.stem+'.obj');name=source.parent.name
        run([nttools/'cl.exe','/nologo','/c','/O1','/Gz','/Zl','/D_X86_=1','/Di386=1','/I'+str(source.parent),'/I'+str(nt/'public/ddk/inc'),'/I'+str(nt/'public/sdk/inc'),'/I'+str(nt/'public/sdk/inc/crt'),'/Fo'+str(obj),source],env=env)
        run([nttools/'link.exe','/nologo','/DRIVER','/SUBSYSTEM:NATIVE','/ENTRY:DriverEntry@8','/NODEFAULTLIB','/ALIGN:32','/OUT:'+str(drivers/(name+'.sys')),obj,nt/'public/ddk/lib/i386/ntoskrnl.lib',nt/'public/ddk/lib/i386/hal.lib'],env=env)
    run([sys.executable,project/'native/hiv/mkhive.py',out/'SYSTEM'])
    shutil.rmtree(out/'work')

