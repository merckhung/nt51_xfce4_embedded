# SPDX-License-Identifier: GPL-2.0-only
"""Package declared NT and rootfs outputs into MBR/FAT16 disks with RAM disk boot."""
from pathlib import Path,PurePosixPath
import gzip,hashlib,io,json,posixpath,shutil,struct,tarfile
from fat16 import Fat16Volume,parse_c_byte_array
from build_common import remove_owned

def extract_alpine(archives,root):
    links={};hardlinks={}
    for archive in sorted(archives.glob('*.apk')):
        raw=gzip.decompress(archive.read_bytes())
        with tarfile.open(fileobj=io.BytesIO(raw),mode='r:',ignore_zeros=True) as tf:
            for member in tf:
                rel=member.name.removeprefix('./').lstrip('/')
                parts=PurePosixPath(rel).parts
                if not parts or '..' in parts or parts[0].startswith('.'):continue
                if ':' in rel:rel=rel.replace(':','_')
                dest=root/rel
                if member.issym():links[rel]=member.linkname
                elif member.islnk():hardlinks[rel]=member.linkname.removeprefix('./').lstrip('/')
                elif member.isfile():
                    dest.parent.mkdir(parents=True,exist_ok=True)
                    with tf.extractfile(member) as source,dest.open('wb') as output:shutil.copyfileobj(source,output)
    # xfconfd relies on Linux signal-driven lifetime handling unavailable in the port.
    # Keep its main loop alive; pinned package plus exact expected bytes make this auditable.
    daemon=root/'usr/lib/xfce4/xfconf/xfconfd'
    data=bytearray(daemon.read_bytes())
    if data[0x780b:0x780d]!=b'\x31\xd2':raise RuntimeError('Unexpected xfconfd binary at keepalive patch offset')
    data[0x780b:0x780d]=b'\xeb\xf7';daemon.write_bytes(data)
    return links,hardlinks

def build(cfg,out,project,nt):
    xfce=cfg['operation']=='xfce_image';variant='rootfs' if xfce else 'minimal_rootfs'
    deps=[Path(f).resolve() for f in cfg['deps']]
    system=next(f for f in deps if f.name=='system.files')
    native=next(f for f in deps if f.name=='native.files')
    boot=next(f for f in deps if f.name=='boot_support.files')
    kernel=next(f for f in deps if f.name=='ntoskrnl.exe')
    hal=next(f for f in deps if f.name=='halacpi.dll')
    work=out/'work';work.mkdir();root=work/'rootfs';root.mkdir()
    links={};hardlinks={}
    if xfce:links,hardlinks=extract_alpine(Path(cfg['alpine']).resolve()/'apks',root)
    shutil.copytree(project/variant/'overlay',root,dirs_exist_ok=True)
    system32=root/'WINDOWS/system32';system32.mkdir(parents=True,exist_ok=True)
    required={kernel:'ntoskrnl.exe',hal:'hal.dll',native/'ntdll.dll':'ntdll.dll',system/'smss.exe':'smss.exe'}
    for source in deps:
        if source.name in ('bootvid.dll','kdcom.dll'):required[source]=source.name
    for name in ('c_1252.nls','c_437.nls','l_intl.nls'):required[boot/name]=name
    for source,dest in required.items():shutil.copy2(source,system32/dest)
    (system32/'config').mkdir();shutil.copy2(system/'SYSTEM',system32/'config/system')
    (system32/'drivers').mkdir()
    for source in boot.glob('*.sys'):shutil.copy2(source,system32/'drivers'/source.name)
    for source in (system/'drivers').glob('*.sys'):
        for dest in (system32/'drivers'/source.name,root/'lib/modules'/source.name):dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source,dest)
    # One real RTL8139 driver, with an explicit alias required by the port's module command.
    if (root/'lib/modules/netdrv.sys').exists():shutil.copy2(root/'lib/modules/netdrv.sys',root/'lib/modules/rtl8139.sys')
    (root/'bin').mkdir(exist_ok=True);shutil.copy2(system/'busybox',root/'bin/busybox');shutil.copy2(system/'nttest.elf',root/'bin/nttest.elf')
    for directory in ('tmp','dev','root','var/run','usr/bin','usr/sbin','sbin','drivers','etc'):(root/directory).mkdir(parents=True,exist_ok=True)
    # The init loader dispatches native processes by this name.
    shutil.copy2(system/'smss.exe',root/'elfloader.exe')
    links['bin/sh']='/bin/busybox';links['bin/nttest']='/bin/busybox';links['usr/bin/nttest']='/bin/busybox'
    for name in ('insmod','rmmod','lsmod','modinfo','ifconfig','route'):links['sbin/'+name]='/bin/busybox'
    for name in ('lsusb','usbinfo','usbctl','ping','wget','nslookup'):links['usr/bin/'+name]='/bin/busybox'
    if xfce:
        links['usr/bin/x11_fb_bridge']='/bin/busybox'
        links['usr/bin/xfce-probe']='/bin/busybox'
    # All enabled BusyBox applets can be invoked through a filesystem path.
    import re
    header=(project/variant/'busybox-config/applet_tables.h').read_text()
    strings=re.findall(r'"([A-Za-z0-9_\[\].+-]+)"\s*"\\0"',header)
    for name in strings:
        if name not in ('gcc','g++','gdb','ssh','scp','sshd','ssh-keygen'):links.setdefault('bin/'+name,'/bin/busybox')
    (root/'etc/symlinks.tab').write_text(''.join('/'+k+'\t'+v+'\n' for k,v in sorted(links.items()) if k!='bin/sh'),newline='\n')
    files={f.relative_to(root).as_posix():{'bytes':f.stat().st_size,'sha256':hashlib.sha256(f.read_bytes()).hexdigest()} for f in sorted(root.rglob('*')) if f.is_file()}
    (out/'rootfs-manifest.json').write_text(json.dumps(files,indent=2)+'\n')
    mbr=parse_c_byte_array(nt/'base/boot/bootcode/mbr/i386/bootmbr.h','x86BootCode')
    fat=parse_c_byte_array(nt/'base/boot/bootcode/fat/i386/bootfat.h','FatBootCode')
    def populate(vol):
        for f in sorted(root.rglob('*')):
            if f.is_dir():vol.mkdir(f.relative_to(root).as_posix())
            elif f.is_file():vol.add_host_file(f.relative_to(root).as_posix(),str(f))
        for _ in range(4):
            for dest,source in sorted({**hardlinks,**links}.items()):
                if dest.upper() in vol.file_map:continue
                target=source.strip('/') if source.startswith('/') else posixpath.normpath(posixpath.join(posixpath.dirname(dest),source)).strip('/')
                if target.upper() in vol.file_map:vol.add_link(dest,target)
    rd_sectors=262144 if xfce else 131072
    rd=Fat16Volume(total_sectors=rd_sectors,boot_sector_template=fat,sectors_per_cluster=8 if xfce else 4,volume_label=b'NT51_RAMDSK')
    populate(rd);rdbytes=rd.finalize();(out/'NTBOOT.IMG').write_bytes(rdbytes)
    total=786432 if xfce else 393216
    vol=Fat16Volume(total_sectors=total-1,boot_sector_template=fat,hidden_sectors=1,sectors_per_cluster=16 if xfce else 8,volume_label=b'NT51_XFCE  ' if xfce else b'NT51_MIN   ')
    vol.add_host_file('NTLDR',str(boot/'ntldr'),attr=0x27);vol.add_host_file('NTDETECT.COM',str(boot/'ntdetect.com'),attr=0x27)
    ini='[boot loader]\r\ntimeout=0\r\ndefault=ramdisk(0)\\WINDOWS\r\n[operating systems]\r\nramdisk(0)\\WINDOWS="NT 5.1 '+variant+'" /FASTDETECT /SOS /NODEBUG /RDPATH=multi(0)disk(0)rdisk(0)partition(1)\\NTBOOT.IMG\r\n'
    vol.add_file('BOOT.INI',ini.encode('ascii'),attr=0x27);vol.add_file('NTBOOT.IMG',rdbytes);populate(vol)
    code=bytearray(mbr);struct.pack_into('<I',code,0x1b8,0x4e543531)
    end=total-1;cyl=min(1023,end//1008);head=(end%1008)//63;sec=(end%63)+1
    code[0x1be:0x1ce]=struct.pack('<BBBBBBBBII',0x80,0,2,0,0x0e,head,((cyl>>8)<<6)|sec,cyl&255,1,total-1)
    code[0x1ce:0x1fe]=bytes(48);code[0x1fe:0x200]=b'\x55\xaa'
    image=out/('xfce_usb.img' if xfce else 'minimal_usb.img')
    with image.open('wb') as stream:stream.write(code);stream.write(vol.finalize())
    remove_owned(work,out)
    print('Built',image,'bytes',image.stat().st_size,flush=True)
