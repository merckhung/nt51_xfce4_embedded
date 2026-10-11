# SPDX-License-Identifier: GPL-2.0-only
from build_common import *

def build_boot(cfg,out,project,nt):
    # build.exe needs a writable source tree. It is an isolated scratch copy of the dependency.
    scratch=Path(out.anchor)/'nt51-build-tmp';scratch.mkdir(exist_ok=True)
    work=Path(tempfile.mkdtemp(prefix='nt-',dir=scratch));copytree(nt,work)
    env=os.environ.copy();env['USERNAME']='bazel';env['NUMBER_OF_PROCESSORS']='12'
    (work/'developer/bazel').mkdir(parents=True,exist_ok=True)
    (work/'developer/bazel/setenv.cmd').write_text('@echo off\n')
    binout=out/'binplace';binout.mkdir()
    stages=['base/published','base/busdrv/pci','base/busdrv/isapnp','base/ntos/rtl/boot','base/ntos/config/boot','base/boot/tftplib','base/boot/lib/daytona','base/boot/bd/daytona','base/boot/bootssp/boot','base/boot/startup/daytona','base/boot/detect/fre','base/boot/bldr/daytona','drivers/storage/ramdisk','base/fs/fastfat/mp','base/fs/npfs/mp','drivers/filters/mountmgr','drivers/storage/partmgr','drivers/storage/classpnp','drivers/storage/disk','drivers/storage/ide','drivers/input/pnpi8042/daytona','drivers/input/kbdclass','drivers/serial/serial','drivers/serial/serenum','drivers/filters/null','drivers/filters/beep']
    # Supply the freshly compiled kernel Ke archive to the original bootloader link.
    ke=next((Path(f) for f in cfg['deps'] if Path(f).name=='ke_up.lib'),None)
    if not ke: raise RuntimeError('Missing Bazel-built ke_up.lib')
    target=work/'base/ntos/ke/up/obj/i386/ke.lib';target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ke,target)
    script=out/'boot-build.cmd'
    lines=['@echo off','setlocal','call "'+str(work/'tools/razzle.cmd')+'" no_urt offline free no_batch','set "_NTTREE='+str(binout)+'"','set "_NT386TREE='+str(binout)+'"']
    for stage in stages:
        lines+=['echo === '+stage+' ===','cd /d "'+str(work/stage)+'"','build -cZ','if errorlevel 1 exit /b 1']
    lines+=['exit /b 0'];script.write_text('\r\n'.join(lines)+'\r\n')
    shell=Path(os.environ['SYSTEMROOT'])/'SysWOW64/cmd.exe'
    log=out/'boot-build.log'
    with log.open('w') as stream:
        result=subprocess.run([shell,'/d','/c',script],env=env,stdout=stream,stderr=subprocess.STDOUT)
    import re
    if result.returncode or re.search(r'nmake.*failed - rc',log.read_text(errors='replace')): raise RuntimeError('NT boot support build failed; see '+str(log)+'\n'+log.read_text(errors='replace')[-5000:])
    # build.exe occasionally returns zero despite errors; inspect every stage and require all outputs.
    errors=[f for f in work.rglob('build.err') if f.stat().st_size]
    if errors: raise RuntimeError('\n'.join(str(f)+'\n'+f.read_text(errors='replace') for f in errors))
    names=['ramdisk.sys','fastfat.sys','npfs.sys','mountmgr.sys','partmgr.sys','classpnp.sys','disk.sys','pciidex.sys','atapi.sys','pciide.sys','intelide.sys','i8042prt.sys','kbdclass.sys','serial.sys','serenum.sys','null.sys','beep.sys','pci.sys','isapnp.sys','ntdetect.com']
    for name in names:
        candidates=[f for f in work.rglob(name) if '/obj/' in f.as_posix()]
        if len(candidates)!=1: raise RuntimeError('Expected one freshly built '+name+': '+str(candidates))
        shutil.copy2(candidates[0],out/name)
    startup=work/'base/boot/startup/daytona/obj/i386/startup.com';osloader=work/'base/boot/bldr/daytona/obj/i386/osloader.exe'
    (out/'ntldr').write_bytes(startup.read_bytes()+osloader.read_bytes())
    for name,source in [('c_1252.nls','codepage/ansi/c_1252.nls'),('c_437.nls','codepage/oem/c_437.nls'),('l_intl.nls','other/l_intl.nls')]:shutil.copy2(work/'base/win32/winnls/data'/source,out/name)
    remove_owned(work,scratch);remove_owned(binout,out)

