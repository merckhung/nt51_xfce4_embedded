# SPDX-License-Identifier: GPL-2.0-only
from build_common import *

def build_boot(cfg,out,project,nt):
    # build.exe needs a writable source tree. It is an isolated scratch copy of the dependency.
    scratch=(Path(out.anchor)/'nt51-build-tmp') if os.name=='nt' else Path('/tmp/nt51-build-tmp');scratch.mkdir(exist_ok=True)
    work=Path(tempfile.mkdtemp(prefix='nt-',dir=scratch));copytree(nt,work)
    if os.name!='nt':
        # The supplied MC passes HeaderFileName to CharPrev while parsing -r/-x,
        # corrupting paths under Wine. Build its patched, pinned source instead.
        mc_out=out/'host-mc';mc_out.mkdir()
        mc_source=work/'sdktools/mc';nttools=work/'tools/x86'
        objects=[]
        for source in sorted(mc_source.glob('*.c')):
            obj=mc_out/(source.stem+'.obj')
            run([nttools/'cl.exe','/nologo','/c','/O1','/MD','/I'+str(work/'public/sdk/inc'),'/I'+str(work/'public/sdk/inc/crt'),'/Fo'+str(obj),source])
            objects.append(obj)
        libs=work/'public/sdk/lib/i386'
        run([nttools/'link.exe','/nologo','/subsystem:console','/nodefaultlib','/out:'+str(mc_out/'mc.exe'),*objects,libs/'msvcrt.lib',libs/'kernel32.lib',libs/'user32.lib',libs/'oldnames.lib'])
        shutil.copy2(mc_out/'mc.exe',nttools/'mc.exe')
    env=os.environ.copy();env['USERNAME']='bazel';env['NUMBER_OF_PROCESSORS']='12'
    (work/'developer/bazel').mkdir(parents=True,exist_ok=True)
    (work/'developer/bazel/setenv.cmd').write_text('@echo off\n')
    binout=out/'binplace';binout.mkdir()
    stages=['base/published','base/busdrv/pci','base/busdrv/isapnp','base/ntos/rtl/boot','base/ntos/config/boot','base/boot/tftplib','base/boot/lib/daytona','base/boot/bd/daytona','base/boot/bootssp/boot','base/boot/startup/daytona','base/boot/detect/fre','base/boot/bldr/daytona','drivers/storage/ramdisk','base/fs/fastfat/mp','base/fs/npfs/mp','drivers/filters/mountmgr','drivers/storage/partmgr','drivers/storage/classpnp','drivers/storage/disk','drivers/storage/ide','drivers/input/pnpi8042/daytona','drivers/input/kbdclass','drivers/serial/serial','drivers/serial/serenum','drivers/filters/null','drivers/filters/beep']
    # Supply the freshly compiled kernel Ke archive to the original bootloader link.
    ke=next((Path(f) for f in cfg['deps'] if Path(f).name=='ke_up.lib'),None)
    if not ke: raise RuntimeError('Missing Bazel-built ke_up.lib')
    target=work/'base/ntos/ke/up/obj/i386/ke.lib';target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ke,target)
    def win_path(p):
        return str(p) if os.name=='nt' else 'Z:'+str(p).replace('/','\\')
    script=out/'boot-build.cmd'
    lines=['@echo off','setlocal','set "PATH=C:\\windows\\system32;C:\\windows;%PATH%"','set "TEMP=C:\\windows\\temp"','set "TMP=C:\\windows\\temp"','set "UseUnsupportedOS=1"','set "PROCESSOR_ARCHITECTURE=x86"','set "NUMBER_OF_PROCESSORS=8"','set "USERNAME=bazel"','call "'+win_path(work/'tools/razzle.cmd')+'" no_urt offline free no_batch temp C:\\windows\\temp binaries_dir "'+win_path(binout)+'"','set "_NTTREE='+win_path(binout)+'"','set "_NT386TREE='+win_path(binout)+'"','set "BINPLACE_LOG='+win_path(binout/'binplace.log')+'"']
    for stage in stages:
        lines+=['echo === '+stage+' ===','cd /d "'+win_path(work/stage)+'"','build -cZ -M 8','if errorlevel 1 exit /b 1']
    lines+=['exit /b 0'];script.write_text('\r\n'.join(lines)+'\r\n')
    log=out/'boot-build.log'
    if os.name=='nt':
        shell=Path(os.environ['SYSTEMROOT'])/'SysWOW64/cmd.exe'
        cmd=[shell,'/d','/c',script]
    else:
        wine=os.environ.get('WINE') or shutil.which('wine') or 'wine'
        env['WINEDEBUG']='-all'
        env.setdefault('WINEPREFIX',str(Path.home()/'.cache/nt51-wine-prefixes/boot_support'))
        # Wine otherwise substitutes its built-in driver during version checks.
        overrides=env.get('WINEDLLOVERRIDES','')
        env['WINEDLLOVERRIDES']=overrides+(';' if overrides else '')+'mountmgr.sys=n'
        cmd=[wine,'cmd.exe','/d','/c',win_path(script)]
    with log.open('w') as stream:
        result=subprocess.run(cmd,env=env,stdout=stream,stderr=subprocess.STDOUT)
    import re
    if result.returncode or re.search(r'nmake.*failed - rc',log.read_text(errors='replace')): raise RuntimeError('NT boot support build failed; see '+str(log)+'\n'+log.read_text(errors='replace')[-5000:])
    # build.exe occasionally returns zero despite errors; inspect every stage and require all outputs.
    errors=[f for f in work.rglob('build.err') if f.stat().st_size]
    if errors: raise RuntimeError('\n'.join(str(f)+'\n'+f.read_text(errors='replace') for f in errors))
    names=['ramdisk.sys','fastfat.sys','npfs.sys','mountmgr.sys','partmgr.sys','classpnp.sys','disk.sys','pciidex.sys','atapi.sys','pciide.sys','intelide.sys','i8042prt.sys','kbdclass.sys','serial.sys','serenum.sys','null.sys','beep.sys','pci.sys','isapnp.sys','ntdetect.com']
    obj_files=[f for f in work.rglob('*') if '/obj/' in f.as_posix() and f.is_file()]
    for name in names:
        candidates=[f for f in obj_files if f.name.lower()==name.lower()]
        if len(candidates)!=1: raise RuntimeError('Expected one freshly built '+name+': '+str(candidates))
        shutil.copy2(candidates[0],out/name)
    startup=work/'base/boot/startup/daytona/obj/i386/startup.com';osloader=work/'base/boot/bldr/daytona/obj/i386/osloader.exe'
    (out/'ntldr').write_bytes(startup.read_bytes()+osloader.read_bytes())
    for name,source in [('c_1252.nls','codepage/ansi/c_1252.nls'),('c_437.nls','codepage/oem/c_437.nls'),('l_intl.nls','other/l_intl.nls')]:shutil.copy2(work/'base/win32/winnls/data'/source,out/name)
    remove_owned(work,scratch);remove_owned(binout,out)

