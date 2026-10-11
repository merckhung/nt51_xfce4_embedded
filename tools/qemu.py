# SPDX-License-Identifier: GPL-2.0-only
"""Launch a project image on the Windows desktop and validate serial test results."""
import argparse,ctypes,json,os,re,socket,subprocess,time,shutil
from ctypes import wintypes
from pathlib import Path

class STARTUPINFOW(ctypes.Structure):
    _fields_=[('cb',wintypes.DWORD),('lpReserved',wintypes.LPWSTR),('lpDesktop',wintypes.LPWSTR),('lpTitle',wintypes.LPWSTR),('dwX',wintypes.DWORD),('dwY',wintypes.DWORD),('dwXSize',wintypes.DWORD),('dwYSize',wintypes.DWORD),('dwXCountChars',wintypes.DWORD),('dwYCountChars',wintypes.DWORD),('dwFillAttribute',wintypes.DWORD),('dwFlags',wintypes.DWORD),('wShowWindow',wintypes.WORD),('cbReserved2',wintypes.WORD),('lpReserved2',ctypes.POINTER(wintypes.BYTE)),('hStdInput',wintypes.HANDLE),('hStdOutput',wintypes.HANDLE),('hStdError',wintypes.HANDLE)]
class PROCESS_INFORMATION(ctypes.Structure):
    _fields_=[('hProcess',wintypes.HANDLE),('hThread',wintypes.HANDLE),('dwProcessId',wintypes.DWORD),('dwThreadId',wintypes.DWORD)]

def spawn(args,cwd):
    if os.name!='nt':return subprocess.Popen(args,cwd=cwd).pid
    k=ctypes.WinDLL('kernel32',use_last_error=True)
    k.CreateProcessW.argtypes=[wintypes.LPCWSTR,wintypes.LPWSTR,ctypes.c_void_p,ctypes.c_void_p,wintypes.BOOL,wintypes.DWORD,ctypes.c_void_p,wintypes.LPCWSTR,ctypes.POINTER(STARTUPINFOW),ctypes.POINTER(PROCESS_INFORMATION)]
    k.CreateProcessW.restype=wintypes.BOOL;k.CloseHandle.argtypes=[wintypes.HANDLE]
    startup=STARTUPINFOW();startup.cb=ctypes.sizeof(startup);startup.lpDesktop='WinSta0\\Default';startup.dwFlags=1;startup.wShowWindow=1
    process=PROCESS_INFORMATION();command=ctypes.create_unicode_buffer(subprocess.list2cmdline(args))
    if not k.CreateProcessW(args[0],command,None,None,False,0x08000000,None,str(cwd),ctypes.byref(startup),ctypes.byref(process)):raise ctypes.WinError(ctypes.get_last_error())
    k.CloseHandle(process.hThread);k.CloseHandle(process.hProcess);return process.dwProcessId

class QMP:
    def __init__(self,port):
        self.sock=socket.create_connection(('127.0.0.1',port),timeout=10);self.file=self.sock.makefile('rwb');self.file.readline();self.call('qmp_capabilities')
    def call(self,command,arguments=None):
        msg={'execute':command}
        if arguments is not None:msg['arguments']=arguments
        self.file.write(json.dumps(msg).encode()+b'\n');self.file.flush()
        while True:
            line=self.file.readline()
            if not line:raise RuntimeError('QMP disconnected')
            reply=json.loads(line)
            if 'error' in reply:raise RuntimeError(str(reply['error']))
            if 'return' in reply:return reply['return']

def main():
    parser=argparse.ArgumentParser();parser.add_argument('variant',choices=['minimal','xfce']);parser.add_argument('--verify',action='store_true');parser.add_argument('--headless',action='store_true');parser.add_argument('--usb',action='store_true',help='Boot the image through an emulated UHCI USB storage device');parser.add_argument('--timeout',type=int,default=180);parser.add_argument('--image',type=Path);args=parser.parse_args()
    project=Path(__file__).resolve().parents[1];variant='minimal_rootfs' if args.variant=='minimal' else 'rootfs'
    image=(args.image or project/'bazel-bin'/variant/'usb_image.files'/(args.variant+'_usb.img')).resolve()
    qemu=os.environ.get('QEMU_BINARY') or shutil.which('qemu-system-i386')
    if not qemu:raise FileNotFoundError('Put qemu-system-i386 on PATH or set QEMU_BINARY')
    if not Path(qemu).is_file() or not image.is_file():raise FileNotFoundError('QEMU or built image missing: '+qemu+'; '+str(image))
    runtime=project/'runtime'/(args.variant+('-usb' if args.usb else ''));runtime.mkdir(parents=True,exist_ok=True);serial=runtime/'serial.log'
    # QEMU locks disks on Windows. Keep the declared Bazel output rebuildable.
    boot_image=runtime/'boot.img';shutil.copyfile(image,boot_image)
    if serial.exists():serial.rename(runtime/('serial-'+str(time.time_ns())+'.log'))
    port=(4465 if args.variant=='minimal' else 4466)+(10 if args.usb else 0)
    drive='file='+str(boot_image)+',format=raw,'+('if=none,id=bootdisk' if args.usb else 'if=ide')
    command=[qemu,'-name','NT 5.1 '+args.variant+(' USB' if args.usb else ''),'-display','none' if args.headless else 'sdl','-m','1536M','-drive',drive,'-snapshot','-vga','std','-serial','file:'+str(serial),'-qmp','tcp:127.0.0.1:'+str(port)+',server=on,wait=off','-netdev','user,id=net0','-device','rtl8139,netdev=net0','-device','piix3-usb-uhci,id=uhci','-no-reboot']
    if args.usb:command+=['-device','usb-storage,drive=bootdisk,bus=uhci.0,bootindex=1']
    pid=spawn(command,project);(runtime/'qemu.json').write_text(json.dumps({'pid':pid,'args':command,'qmp_port':port},indent=2)+'\n');print('QEMU started PID',pid,'log',serial,flush=True)
    if not args.verify:return
    result={'variant':args.variant,'boot_device':'usb' if args.usb else 'ide','image_sha256':__import__('hashlib').sha256(boot_image.read_bytes()).hexdigest(),'passed':False,'pid':pid}
    deadline=time.monotonic()+args.timeout
    while time.monotonic()<deadline:
        text=serial.read_text(errors='replace') if serial.exists() else ''
        if '[init] NTTEST_EXIT=' in text:
            suites=re.search(r'Subsystem Suites:\s*(\d+) total \| (\d+) passed \| (\d+) failed',text)
            tests=re.search(r'Individual Tests:\s*(\d+) total \| (\d+) passed \| (\d+) failed',text)
            exitcode=re.search(r'\[init\] NTTEST_EXIT=(\d+)',text)
            result.update({'suites':list(map(int,suites.groups())) if suites else None,'tests':list(map(int,tests.groups())) if tests else None,'exit_code':int(exitcode[1]) if exitcode else None})
            result['kernel_tests_passed']=bool(suites and tests and result['suites']==[9,9,0] and result['tests'][0]>0 and result['tests'][0]==result['tests'][1] and result['tests'][2]==0 and result['exit_code']==0)
            ps_exit=re.search(r'\[rc.sysinit\] PS_AUX_EXIT=(\d+)',text)
            result['ps_aux_exit_code']=int(ps_exit[1]) if ps_exit else None
            result['passed']=result['kernel_tests_passed'] and result['ps_aux_exit_code']==0
            if args.variant=='xfce' and result['passed']:
                if '[x11_fb_bridge] XTEST ready op=' not in text:
                    time.sleep(1)
                    continue
                result['x11_transport_ready']=True
                desktop=re.search(r'\[xfce-probe\] READY top_panel=(\d+) bottom_panel=(\d+) terminal=(\d+) desktop=(\d+)',text)
                if not desktop:
                    time.sleep(1)
                    continue
                result['visible_xfce_windows']=dict(zip(('top_panel','bottom_panel','terminal','desktop'),map(int,desktop.groups())))
                result['xfce_desktop_ready']=all(result['visible_xfce_windows'].values())
                result['passed']=result['kernel_tests_passed'] and result['ps_aux_exit_code']==0 and result['xfce_desktop_ready']
                time.sleep(3)
            break
        time.sleep(1)
    else:
        result['passed']=False
        result['error']='Timed out waiting for kernel tests or the required visible XFCE windows'
    try:
        qmp=QMP(port);qmp.call('screendump',{'filename':str(runtime/'screen.png'),'format':'png'})
    except Exception as error:result['screenshot_error']=str(error)
    (runtime/'verification.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2),flush=True)
    if not result['passed']:raise SystemExit(1)

if __name__=='__main__':main()
